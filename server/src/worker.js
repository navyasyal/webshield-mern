import {
  Worker,
} from "bullmq";

import IORedis from "ioredis";

import {
  connectDb,
  Scan,
} from "./db.js";

import {
  scanSite,
} from "./scanner.js";

import {
  dynamicCrawl,
} from "./playwrightCrawler.js";


// ======================================================
// Configuration
// ======================================================

const REDIS_URL =
  process.env.REDIS_URL ||
  "redis://redis:6379";


const PROGRESS_CHANNEL =
  "webshield:scan-progress";


// ======================================================
// Redis Connections
// ======================================================

const connection =
  new IORedis(
    REDIS_URL,
    {
      maxRetriesPerRequest:
        null,
    }
  );


const progressPublisher =
  new IORedis(
    REDIS_URL,
    {
      maxRetriesPerRequest:
        null,
    }
  );


// ======================================================
// Publish Progress
// ======================================================

async function publishProgress(
  scan
) {
  await progressPublisher.publish(
    PROGRESS_CHANNEL,

    JSON.stringify({
      scanId:
        scan._id.toString(),

      owner:
        scan.owner.toString(),

      status:
        scan.status,

      percent:
        scan.progress?.percent ??
        0,

      stage:
        scan.progress?.stage ||
        "",

      message:
        scan.progress?.message ||
        "",
    })
  );
}


// ======================================================
// Update Progress
// ======================================================

async function updateProgress(
  scan,
  percent,
  stage,
  message
) {
  scan.progress = {
    percent,
    stage,
    message,
  };


  await scan.save();


  await publishProgress(
    scan
  );
}


// ======================================================
// Get Scan ID From BullMQ Job
//
// Supports:
// job.data.scanId
// job.data.id
// job.id
// ======================================================

function getScanId(
  job
) {
  const scanId =
    job?.data?.scanId ||
    job?.data?.id ||
    job?.id;


  if (
    !scanId
  ) {
    throw new Error(
      "BullMQ job does not contain a scan ID"
    );
  }


  return String(
    scanId
  );
}


// ======================================================
// Finding Snapshot
// ======================================================

function snapshotFinding(
  finding
) {
  return {
    fingerprint:
      finding.fingerprint ||
      "",

    code:
      finding.code ||
      "",

    title:
      finding.title ||
      "",

    severity:
      finding.severity ||
      "",

    owasp:
      finding.owasp ||
      "",

    url:
      finding.url ||
      "",
  };
}


// ======================================================
// Compare Scan With Previous Completed Scan
// ======================================================

async function buildComparison(
  scan,
  currentFindings
) {
  const previousScan =
    await Scan
      .findOne({
        _id: {
          $ne:
            scan._id,
        },

        owner:
          scan.owner,

        url:
          scan.url,

        status:
          "completed",
      })
      .sort({
        finishedAt:
          -1,

        createdAt:
          -1,
      })
      .lean();


  // ====================================================
  // First scan / baseline
  // ====================================================

  if (
    !previousScan
  ) {
    return {
      hasPreviousScan:
        false,

      previousScanId:
        null,

      previousFinishedAt:
        null,

      newCount:
        currentFindings.length,

      resolvedCount:
        0,

      unchangedCount:
        0,

      newFindings:
        currentFindings.map(
          snapshotFinding
        ),

      resolvedFindings:
        [],

      unchangedFindings:
        [],
    };
  }


  const previousFindings =
    previousScan.findings ||
    [];


  const currentMap =
    new Map();


  const previousMap =
    new Map();


  // ----------------------------------------------------
  // Current findings
  // ----------------------------------------------------

  for (
    const finding
    of currentFindings
  ) {
    if (
      finding.fingerprint
    ) {
      currentMap.set(
        finding.fingerprint,
        finding
      );
    }
  }


  // ----------------------------------------------------
  // Previous findings
  // ----------------------------------------------------

  for (
    const finding
    of previousFindings
  ) {
    if (
      finding.fingerprint
    ) {
      previousMap.set(
        finding.fingerprint,
        finding
      );
    }
  }


  const newFindings =
    [];


  const resolvedFindings =
    [];


  const unchangedFindings =
    [];


  // ====================================================
  // New + Unchanged
  // ====================================================

  for (
    const [
      fingerprint,
      finding,
    ]
    of currentMap
  ) {
    if (
      previousMap.has(
        fingerprint
      )
    ) {
      unchangedFindings.push(
        snapshotFinding(
          finding
        )
      );

    } else {
      newFindings.push(
        snapshotFinding(
          finding
        )
      );
    }
  }


  // ====================================================
  // Resolved
  // ====================================================

  for (
    const [
      fingerprint,
      finding,
    ]
    of previousMap
  ) {
    if (
      !currentMap.has(
        fingerprint
      )
    ) {
      resolvedFindings.push(
        snapshotFinding(
          finding
        )
      );
    }
  }


  return {
    hasPreviousScan:
      true,

    previousScanId:
      previousScan._id,

    previousFinishedAt:
      previousScan.finishedAt ||
      previousScan.createdAt ||
      null,

    newCount:
      newFindings.length,

    resolvedCount:
      resolvedFindings.length,

    unchangedCount:
      unchangedFindings.length,

    newFindings,

    resolvedFindings,

    unchangedFindings,
  };
}


// ======================================================
// Severity Summary
// ======================================================

function buildSeveritySummary(
  findings
) {
  const summary = {
    critical:
      0,

    high:
      0,

    medium:
      0,

    low:
      0,

    info:
      0,
  };


  for (
    const finding
    of findings
  ) {
    const severity =
      (
        finding.severity ||
        ""
      )
        .trim()
        .toLowerCase();


    if (
      severity ===
      "critical"
    ) {
      summary.critical +=
        1;

    } else if (
      severity ===
      "high"
    ) {
      summary.high +=
        1;

    } else if (
      severity ===
      "medium"
    ) {
      summary.medium +=
        1;

    } else if (
      severity ===
      "low"
    ) {
      summary.low +=
        1;

    } else {
      summary.info +=
        1;
    }
  }


  return summary;
}


// ======================================================
// Security Score
// ======================================================

function calculateSecurityScore(
  summary
) {
  const penalty =
    (
      summary.critical *
      20
    ) +
    (
      summary.high *
      10
    ) +
    (
      summary.medium *
      5
    ) +
    (
      summary.low *
      2
    );


  return Math.max(
    0,
    Math.min(
      100,
      100 - penalty
    )
  );
}


// ======================================================
// Connect Database
// ======================================================

await connectDb();


// ======================================================
// Worker
// ======================================================

const worker =
  new Worker(
    "scans",

    async (
      job
    ) => {

      // ==================================================
      // IMPORTANT FIX
      // ==================================================

      const scanId =
        getScanId(
          job
        );


      console.log(
        `Processing scan job ${job.id} for scan ${scanId}`
      );


      const scan =
        await Scan.findById(
          scanId
        );


      if (
        !scan
      ) {
        throw new Error(
          `Scan not found: ${scanId}`
        );
      }


      try {

        // ================================================
        // Start
        // ================================================

        scan.status =
          "running";


        scan.startedAt =
          new Date();


        scan.finishedAt =
          null;


        scan.error =
          null;


        await updateProgress(
          scan,
          5,
          "Starting",
          "Preparing scanner engine"
        );


        // ================================================
        // Target Validation
        // ================================================

        await updateProgress(
          scan,
          15,
          "Target Validation",
          "Validating authorized target"
        );


        // ================================================
        // Security Scanner
        // ================================================

        await updateProgress(
          scan,
          25,
          "Security Analysis",
          "Running passive and active security checks"
        );


        const scannerResult =
          await scanSite(
            scan.url
          );


        await updateProgress(
          scan,
          45,
          "Security Analysis",
          "Passive and active checks completed"
        );


        // ================================================
        // Dynamic Playwright Crawl
        // ================================================

        await updateProgress(
          scan,
          55,
          "Dynamic Crawling",
          "Launching browser-based application discovery"
        );


        const dynamicResult =
          await dynamicCrawl(
            scan.url
          );


        await updateProgress(
          scan,
          70,
          "Discovery Completed",
          "Pages, forms and API requests discovered"
        );


        // ================================================
        // Merge Page Discovery
        // ================================================

        const pages =
          [
            ...new Set([
              ...(
                scannerResult.pages ||
                []
              ),

              ...(
                dynamicResult.pages ||
                []
              ),
            ]),
          ];


        const forms =
          dynamicResult.forms ||
          [];


        const apiRequests =
          dynamicResult.apiRequests ||
          [];


        const findings =
          scannerResult.findings ||
          [];


        // ================================================
        // Analyze Findings
        // ================================================

        await updateProgress(
          scan,
          80,
          "Findings Analysis",
          "Analyzing severity and vulnerability changes"
        );


        const severitySummary =
          buildSeveritySummary(
            findings
          );


        const securityScore =
          calculateSecurityScore(
            severitySummary
          );


        // ================================================
        // Regression Comparison
        // ================================================

        const comparison =
          await buildComparison(
            scan,
            findings
          );


        // ================================================
        // Save Results
        // ================================================

        await updateProgress(
          scan,
          90,
          "Saving Results",
          "Saving scan findings and comparison results"
        );


        scan.pages =
          pages;


        scan.discovery = {
          forms,
          apiRequests,
        };


        scan.findings =
          findings;


        scan.summary = {
          critical:
            severitySummary.critical,

          high:
            severitySummary.high,

          medium:
            severitySummary.medium,

          low:
            severitySummary.low,

          info:
            severitySummary.info,

          pages:
            pages.length,

          forms:
            forms.length,

          apiRequests:
            apiRequests.length,
        };


        scan.securityScore =
          securityScore;


        scan.comparison =
          comparison;


        scan.status =
          "completed";


        scan.finishedAt =
          new Date();


        scan.progress = {
          percent:
            100,

          stage:
            "Completed",

          message:
            "Security scan and vulnerability comparison completed successfully",
        };


        await scan.save();


        await publishProgress(
          scan
        );


        console.log(
          [
            `Scan ${scan._id} completed.`,
            `Findings: ${findings.length}.`,
            `Score: ${securityScore}/100.`,
            `New: ${comparison.newCount}.`,
            `Resolved: ${comparison.resolvedCount}.`,
            `Unchanged: ${comparison.unchangedCount}.`,
          ].join(
            " "
          )
        );


        return {
          scanId:
            scan._id.toString(),

          status:
            "completed",

          findings:
            findings.length,

          securityScore,

          comparison: {
            new:
              comparison.newCount,

            resolved:
              comparison.resolvedCount,

            unchanged:
              comparison.unchangedCount,
          },
        };

      } catch (
        error
      ) {

        console.error(
          `Scan ${scanId} failed:`,
          error
        );


        scan.status =
          "failed";


        scan.error =
          error?.message ||
          "Scanner worker failed";


        scan.finishedAt =
          new Date();


        scan.progress = {
          percent:
            100,

          stage:
            "Failed",

          message:
            scan.error,
        };


        await scan.save();


        await publishProgress(
          scan
        );


        throw error;
      }
    },

    {
      connection,

      concurrency:
        2,
    }
  );


// ======================================================
// Worker Events
// ======================================================

worker.on(
  "active",

  (
    job
  ) => {

    console.log(
      `Worker started job ${job.id}`
    );

  }
);


worker.on(
  "completed",

  (
    job
  ) => {

    console.log(
      `Worker job ${job.id} completed`
    );

  }
);


worker.on(
  "failed",

  (
    job,
    error
  ) => {

    console.error(
      `Worker job ${job?.id} failed:`,
      error?.message
    );

  }
);


worker.on(
  "error",

  (
    error
  ) => {

    console.error(
      "Worker error:",
      error
    );

  }
);


// ======================================================
// Ready
// ======================================================

console.log(
  "WebShield scanner worker ready"
);