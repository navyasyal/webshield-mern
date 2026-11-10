import {
  Worker,
} from "bullmq";

import Redis from "ioredis";

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
  "redis://localhost:6379";


// ======================================================
// Database
// ======================================================

await connectDb();


// ======================================================
// Redis Publisher
// ======================================================

const publisher =
  new Redis(
    REDIS_URL
  );


// ======================================================
// Update Scan Progress
// ======================================================

async function updateProgress(
  scan,
  percent,
  stage,
  message
) {
  const progress = {
    percent,
    stage,
    message,
  };

  await Scan.updateOne(
    {
      _id: scan._id,
    },
    {
      progress,
    }
  );

  await publisher.publish(
    "webshield:scan-progress",

    JSON.stringify({
      scanId:
        String(
          scan._id
        ),

      owner:
        String(
          scan.owner
        ),

      status:
        "running",

      percent,
      stage,
      message,
    })
  );
}


// ======================================================
// Worker
// ======================================================

const worker =
  new Worker(
    "scans",

    async (job) => {
      const scan =
        await Scan.findById(
          job.data.id
        );

      if (!scan) {
        console.error(
          "Scan not found:",
          job.data.id
        );

        return;
      }


      // --------------------------------------------
      // Start
      // --------------------------------------------

      await Scan.updateOne(
        {
          _id: scan._id,
        },
        {
          status:
            "running",

          startedAt:
            new Date(),

          error:
            null,

          progress: {
            percent:
              5,

            stage:
              "Starting",

            message:
              "Scanner worker started",
          },
        }
      );


      await publisher.publish(
        "webshield:scan-progress",

        JSON.stringify({
          scanId:
            String(
              scan._id
            ),

          owner:
            String(
              scan.owner
            ),

          status:
            "running",

          percent:
            5,

          stage:
            "Starting",

          message:
            "Scanner worker started",
        })
      );


      try {

        // --------------------------------------------
        // Target Validation
        // --------------------------------------------

        await updateProgress(
          scan,
          15,
          "Target Validation",
          "Validating scan target"
        );


        // --------------------------------------------
        // Passive Scan
        // --------------------------------------------

        await updateProgress(
          scan,
          25,
          "Passive Scan",
          "Checking security headers, cookies and configuration"
        );


        const passiveResult =
          await scanSite(
            scan.url
          );


        await updateProgress(
          scan,
          45,
          "Passive Scan",
          "Passive security checks completed"
        );


        // --------------------------------------------
        // Playwright Dynamic Crawl
        // --------------------------------------------

        await updateProgress(
          scan,
          55,
          "Dynamic Crawling",
          "Launching Playwright browser crawler"
        );


        const dynamicResult =
          await dynamicCrawl(
            scan.url
          );


        await updateProgress(
          scan,
          70,
          "Dynamic Crawling",
          "Page, form and API discovery completed"
        );


        // --------------------------------------------
        // Merge Pages
        // --------------------------------------------

        const pages = [
          ...new Set([
            ...(
              passiveResult.pages ||
              []
            ),

            ...(
              dynamicResult.pages ||
              []
            ),
          ]),
        ];


        const findings =
          passiveResult
            .findings ||
          [];


        const forms =
          dynamicResult
            .forms ||
          [];


        const apiRequests =
          dynamicResult
            .apiRequests ||
          [];


        // --------------------------------------------
        // Analyze Findings
        // --------------------------------------------

        await updateProgress(
          scan,
          80,
          "Findings Analysis",
          "Analyzing vulnerability severity"
        );


        const critical =
          findings.filter(
            (finding) =>
              finding.severity ===
              "Critical"
          ).length;


        const high =
          findings.filter(
            (finding) =>
              finding.severity ===
              "High"
          ).length;


        const medium =
          findings.filter(
            (finding) =>
              finding.severity ===
              "Medium"
          ).length;


        const low =
          findings.filter(
            (finding) =>
              finding.severity ===
              "Low"
          ).length;


        const informational =
          findings.filter(
            (finding) =>
              finding.severity ===
              "Informational"
          ).length;


        // --------------------------------------------
        // Security Score
        // --------------------------------------------

        let securityScore =
          100 -
          critical * 20 -
          high * 10 -
          medium * 5 -
          low * 2;


        securityScore =
          Math.max(
            0,
            Math.min(
              100,
              securityScore
            )
          );


        // --------------------------------------------
        // Save
        // --------------------------------------------

        await updateProgress(
          scan,
          90,
          "Saving Results",
          "Saving assessment results"
        );


        await Scan.updateOne(
          {
            _id: scan._id,
          },

          {
            status:
              "completed",

            pages,

            discovery: {
              forms,
              apiRequests,
            },

            findings,

            summary: {
              totalFindings:
                findings.length,

              critical,

              high,

              medium,

              low,

              informational,

              pagesDiscovered:
                pages.length,

              formsDiscovered:
                forms.length,

              apiRequestsDiscovered:
                apiRequests.length,
            },

            securityScore,

            progress: {
              percent:
                100,

              stage:
                "Completed",

              message:
                "Security scan completed successfully",
            },

            error:
              null,

            finishedAt:
              new Date(),
          }
        );


        // --------------------------------------------
        // Completion Event
        // --------------------------------------------

        await publisher.publish(
          "webshield:scan-progress",

          JSON.stringify({
            scanId:
              String(
                scan._id
              ),

            owner:
              String(
                scan.owner
              ),

            status:
              "completed",

            percent:
              100,

            stage:
              "Completed",

            message:
              "Security scan completed successfully",
          })
        );


        console.log(
          `Scan completed: ${scan._id}`
        );

        console.log(
          `Pages discovered: ${pages.length}`
        );

        console.log(
          `Forms discovered: ${forms.length}`
        );

        console.log(
          `API requests discovered: ${apiRequests.length}`
        );

        console.log(
          `Findings: ${findings.length}`
        );

        console.log(
          `Security score: ${securityScore}`
        );

      } catch (error) {

        console.error(
          `Scan failed ${scan._id}:`,
          error
        );


        const errorMessage =
          String(
            error?.message ||
            "Unknown scanner error"
          ).slice(
            0,
            300
          );


        await Scan.updateOne(
          {
            _id:
              scan._id,
          },

          {
            status:
              "failed",

            progress: {
              percent:
                100,

              stage:
                "Failed",

              message:
                errorMessage,
            },

            error:
              errorMessage,

            finishedAt:
              new Date(),
          }
        );


        await publisher.publish(
          "webshield:scan-progress",

          JSON.stringify({
            scanId:
              String(
                scan._id
              ),

            owner:
              String(
                scan.owner
              ),

            status:
              "failed",

            percent:
              100,

            stage:
              "Failed",

            message:
              errorMessage,
          })
        );


        throw error;
      }
    },

    {
      connection: {
        url:
          REDIS_URL,

        maxRetriesPerRequest:
          null,
      },

      concurrency:
        1,
    }
  );


// ======================================================
// Worker Events
// ======================================================

worker.on(
  "completed",
  (job) => {
    console.log(
      `Worker completed job: ${job.id}`
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
      `Worker failed job ${
        job?.id ||
        "unknown"
      }:`,
      error.message
    );
  }
);


worker.on(
  "error",
  (error) => {
    console.error(
      "Worker error:",
      error
    );
  }
);


console.log(
  "WebShield scanner worker ready"
);