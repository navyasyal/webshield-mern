import PDFDocument from "pdfkit";


// ======================================================
// Theme
// ======================================================

const COLORS = {
  navy: "#0F172A",
  navySoft: "#1E293B",

  blue: "#2563EB",
  blueSoft: "#EFF6FF",

  slate: "#475569",
  muted: "#64748B",

  light: "#F8FAFC",
  border: "#E2E8F0",
  white: "#FFFFFF",

  critical: "#7F1D1D",
  high: "#B91C1C",
  medium: "#B45309",
  low: "#1D4ED8",
  info: "#475569",

  redSoft: "#FEF2F2",
  amberSoft: "#FFFBEB",
  green: "#047857",
  greenSoft: "#ECFDF5",
};


const SEVERITY_RANK = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};


// ======================================================
// Utilities
// ======================================================

function safeText(
  value,
  fallback = "N/A"
) {
  if (
    value === undefined ||
    value === null ||
    String(value).trim() === ""
  ) {
    return fallback;
  }

  return String(value);
}


function formatDate(
  value
) {
  if (!value) {
    return "N/A";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "N/A";
  }

  return date.toLocaleString(
    "en-IN",
    {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "Asia/Kolkata",
    }
  );
}


function contentWidth(
  doc
) {
  return (
    doc.page.width -
    doc.page.margins.left -
    doc.page.margins.right
  );
}


function contentBottom(
  doc
) {
  return (
    doc.page.height -
    doc.page.margins.bottom
  );
}


function ensureSpace(
  doc,
  requiredHeight = 100
) {
  if (
    doc.y +
      requiredHeight >
    contentBottom(doc)
  ) {
    doc.addPage();

    drawPageAccent(
      doc
    );
  }
}


// ======================================================
// Severity Helpers
// ======================================================

function severityColor(
  severity
) {
  switch (
    severity
  ) {
    case "Critical":
      return COLORS.critical;

    case "High":
      return COLORS.high;

    case "Medium":
      return COLORS.medium;

    case "Low":
      return COLORS.low;

    default:
      return COLORS.info;
  }
}


function severityBackground(
  severity
) {
  switch (
    severity
  ) {
    case "Critical":
    case "High":
      return COLORS.redSoft;

    case "Medium":
      return COLORS.amberSoft;

    case "Low":
      return COLORS.blueSoft;

    default:
      return COLORS.light;
  }
}


function securityRating(
  score
) {
  if (
    score >= 90
  ) {
    return {
      label: "Strong",
      color: COLORS.green,
    };
  }

  if (
    score >= 75
  ) {
    return {
      label: "Good",
      color: COLORS.blue,
    };
  }

  if (
    score >= 50
  ) {
    return {
      label:
        "Needs Improvement",
      color:
        COLORS.medium,
    };
  }

  return {
    label: "High Risk",
    color: COLORS.high,
  };
}


// ======================================================
// Finding Analysis
// ======================================================

function buildSeverityCounts(
  findings = []
) {
  const result = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };

  for (
    const finding
    of findings
  ) {
    const severity =
      safeText(
        finding.severity,
        "Info"
      );

    if (
      Object.prototype
        .hasOwnProperty
        .call(
          result,
          severity
        )
    ) {
      result[
        severity
      ] += 1;
    } else {
      result.Info +=
        1;
    }
  }

  return result;
}


function buildOwaspSummary(
  findings = []
) {
  const map =
    new Map();

  for (
    const finding
    of findings
  ) {
    const owasp =
      safeText(
        finding.owasp,
        "Unmapped"
      );

    map.set(
      owasp,
      (
        map.get(
          owasp
        ) ||
        0
      ) + 1
    );
  }

  return [
    ...map.entries(),
  ].sort(
    (
      first,
      second
    ) =>
      second[1] -
      first[1]
  );
}


// ======================================================
// Group Repeated Findings
//
// Example:
// MISSING_CSP on 5 pages becomes ONE issue with 5 URLs.
// ======================================================

function groupFindings(
  findings = []
) {
  const groups =
    new Map();

  for (
    const finding
    of findings
  ) {
    const key =
      finding.code ||
      [
        finding.title,
        finding.severity,
        finding.owasp,
      ].join("|");

    if (
      !groups.has(
        key
      )
    ) {
      groups.set(
        key,
        {
          key,

          code:
            safeText(
              finding.code
            ),

          title:
            safeText(
              finding.title
            ),

          severity:
            safeText(
              finding.severity,
              "Info"
            ),

          confidence:
            safeText(
              finding.confidence
            ),

          owasp:
            safeText(
              finding.owasp,
              "Unmapped"
            ),

          remediation:
            safeText(
              finding.remediation
            ),

          urls:
            new Set(),

          evidences:
            new Set(),

          observations:
            0,
        }
      );
    }


    const group =
      groups.get(
        key
      );


    group.observations +=
      1;


    if (
      finding.url
    ) {
      group.urls.add(
        String(
          finding.url
        )
      );
    }


    if (
      finding.evidence
    ) {
      group.evidences.add(
        String(
          finding.evidence
        )
      );
    }


    const existingRank =
      SEVERITY_RANK[
        group.severity
      ] ||
      0;


    const currentSeverity =
      safeText(
        finding.severity,
        "Info"
      );


    const currentRank =
      SEVERITY_RANK[
        currentSeverity
      ] ||
      0;


    if (
      currentRank >
      existingRank
    ) {
      group.severity =
        currentSeverity;
    }
  }


  return [
    ...groups.values(),
  ]
    .map(
      (
        group
      ) => ({
        ...group,

        urls: [
          ...group.urls,
        ],

        evidences: [
          ...group.evidences,
        ],
      })
    )
    .sort(
      (
        first,
        second
      ) => {

        const severityDifference =
          (
            SEVERITY_RANK[
              second.severity
            ] ||
            0
          ) -
          (
            SEVERITY_RANK[
              first.severity
            ] ||
            0
          );


        if (
          severityDifference !==
          0
        ) {
          return severityDifference;
        }


        return first.title.localeCompare(
          second.title
        );
      }
    );
}


// ======================================================
// Executive Summary
// ======================================================

function buildExecutiveSummary(
  findings,
  grouped,
  severityCounts
) {
  const total =
    findings.length;

  const unique =
    grouped.length;

  const highImpact =
    severityCounts.Critical +
    severityCounts.High;


  if (
    total === 0
  ) {
    return (
      "The WebShield assessment completed without identifying a security finding " +
      "under the currently enabled automated checks. This result should be " +
      "interpreted within the tested scope and does not guarantee that the " +
      "application is free from vulnerabilities."
    );
  }


  if (
    highImpact >
    0
  ) {
    return (
      `WebShield identified ${total} security observations representing ` +
      `${unique} unique issue type(s). ${highImpact} observation(s) were ` +
      "classified as Critical or High severity. Remediation should prioritize " +
      "high-impact vulnerabilities first, followed by recurring security " +
      "misconfigurations affecting multiple application routes."
    );
  }


  return (
    `WebShield identified ${total} security observations representing ` +
    `${unique} unique issue type(s). No Critical or High severity issue was ` +
    "identified by the enabled checks. Medium and Low severity issues should " +
    "still be remediated to strengthen the application's overall security posture."
  );
}


// ======================================================
// Common Drawing Helpers
// ======================================================

function drawPageAccent(
  doc
) {
  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );


  doc.save();

  doc
    .rect(
      left,
      40,
      width,
      3
    )
    .fill(
      COLORS.blue
    );

  doc.restore();


  doc.y =
    58;
}


function drawSectionHeader(
  doc,
  number,
  title,
  subtitle = ""
) {
  ensureSpace(
    doc,
    subtitle
      ? 90
      : 70
  );


  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );

  const startY =
    doc.y;


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      9
    )
    .fillColor(
      COLORS.blue
    )
    .text(
      String(
        number
      ).padStart(
        2,
        "0"
      ),
      left,
      startY +
        2,
      {
        width: 28,
      }
    );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      17
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      title,
      left +
        34,
      startY,
      {
        width:
          width -
          34,
      }
    );


  doc.y =
    startY +
    28;


  if (
    subtitle
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        9
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        subtitle,
        left +
          34,
        doc.y,
        {
          width:
            width -
            34,

          lineGap:
            2,
        }
      );

    doc.moveDown(
      0.5
    );
  }


  const lineY =
    doc.y +
    5;


  doc.save();

  doc
    .moveTo(
      left,
      lineY
    )
    .lineTo(
      left +
        width,
      lineY
    )
    .lineWidth(
      0.7
    )
    .strokeColor(
      COLORS.border
    )
    .stroke();

  doc.restore();


  doc.y =
    lineY +
    16;
}


// ======================================================
// Metric Card
// ======================================================

function drawMetricCard(
  doc,
  x,
  y,
  width,
  height,
  label,
  value,
  note = "",
  accent =
    COLORS.blue
) {
  doc.save();

  doc
    .roundedRect(
      x,
      y,
      width,
      height,
      8
    )
    .fillAndStroke(
      COLORS.white,
      COLORS.border
    );

  doc
    .rect(
      x,
      y,
      4,
      height
    )
    .fill(
      accent
    );

  doc.restore();


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      7.8
    )
    .fillColor(
      COLORS.muted
    )
    .text(
      String(
        label
      ).toUpperCase(),
      x +
        14,
      y +
        11,
      {
        width:
          width -
          25,
      }
    );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      18
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      String(
        value
      ),
      x +
        14,
      y +
        29,
      {
        width:
          width -
          25,
      }
    );


  if (
    note
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        7
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        note,
        x +
          14,
        y +
          height -
          17,
        {
          width:
            width -
            25,
        }
      );
  }
}


// ======================================================
// Severity Cards
// ======================================================

function drawSeverityStrip(
  doc,
  counts
) {
  const labels = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Info",
  ];


  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );

  const gap =
    7;

  const cardWidth =
    (
      width -
      gap *
        (
          labels.length -
          1
        )
    ) /
    labels.length;


  const startY =
    doc.y;


  labels.forEach(
    (
      severity,
      index
    ) => {

      const x =
        left +
        index *
          (
            cardWidth +
            gap
          );


      doc.save();

      doc
        .roundedRect(
          x,
          startY,
          cardWidth,
          58,
          7
        )
        .fillAndStroke(
          severityBackground(
            severity
          ),
          COLORS.border
        );

      doc.restore();


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          16
        )
        .fillColor(
          severityColor(
            severity
          )
        )
        .text(
          String(
            counts[
              severity
            ] ||
            0
          ),
          x +
            5,
          startY +
            10,
          {
            width:
              cardWidth -
              10,

            align:
              "center",
          }
        );


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          7
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          severity.toUpperCase(),
          x +
            5,
          startY +
            36,
          {
            width:
              cardWidth -
              10,

            align:
              "center",
          }
        );
    }
  );


  doc.y =
    startY +
    76;
}


// ======================================================
// Key Value Rows
// ======================================================

function drawKeyValueRows(
  doc,
  rows
) {
  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );

  const labelWidth =
    150;


  for (
    const [
      label,
      value,
    ]
    of rows
  ) {
    ensureSpace(
      doc,
      35
    );


    const startY =
      doc.y;


    doc
      .font(
        "Helvetica-Bold"
      )
      .fontSize(
        8
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        String(
          label
        ).toUpperCase(),
        left,
        startY,
        {
          width:
            labelWidth,
        }
      );


    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        9
      )
      .fillColor(
        COLORS.slate
      )
      .text(
        safeText(
          value
        ),
        left +
          labelWidth,
        startY,
        {
          width:
            width -
            labelWidth,

          lineGap:
            2,
        }
      );


    doc.y =
      Math.max(
        doc.y,
        startY +
          18
      );


    doc.save();

    doc
      .moveTo(
        left,
        doc.y
      )
      .lineTo(
        left +
          width,
        doc.y
      )
      .lineWidth(
        0.35
      )
      .strokeColor(
        COLORS.border
      )
      .stroke();

    doc.restore();


    doc.y +=
      8;
  }
}


// ======================================================
// OWASP Table
// ======================================================

function drawOwaspTable(
  doc,
  rows
) {
  if (
    rows.length ===
    0
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        9
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        "No OWASP-mapped findings were recorded."
      );

    return;
  }


  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );


  const headerY =
    doc.y;


  doc.save();

  doc
    .roundedRect(
      left,
      headerY,
      width,
      30,
      4
    )
    .fill(
      COLORS.navy
    );

  doc.restore();


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      8
    )
    .fillColor(
      COLORS.white
    )
    .text(
      "OWASP CATEGORY",
      left +
        10,
      headerY +
        10,
      {
        width:
          width -
          110,
      }
    );


  doc
    .text(
      "OBSERVATIONS",
      left +
        width -
        100,
      headerY +
        10,
      {
        width:
          90,

        align:
          "right",
      }
    );


  doc.y =
    headerY +
    38;


  rows.forEach(
    (
      [
        category,
        count,
      ],
      index
    ) => {

      ensureSpace(
        doc,
        36
      );


      const rowY =
        doc.y;


      if (
        index %
          2 ===
        0
      ) {
        doc.save();

        doc
          .rect(
            left,
            rowY -
              3,
            width,
            29
          )
          .fill(
            COLORS.light
          );

        doc.restore();
      }


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          8.7
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          category,
          left +
            10,
          rowY +
            5,
          {
            width:
              width -
              120,
          }
        );


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          9
        )
        .fillColor(
          COLORS.navy
        )
        .text(
          String(
            count
          ),
          left +
            width -
            90,
          rowY +
            5,
          {
            width:
              80,

            align:
              "right",
          }
        );


      doc.y =
        rowY +
        31;
    }
  );
}


// ======================================================
// Findings Overview Table
// ======================================================

function drawFindingsOverviewTable(
  doc,
  grouped
) {
  if (
    grouped.length ===
    0
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        9
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        "No findings were recorded."
      );

    return;
  }


  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );


  const idWidth =
    55;

  const severityWidth =
    65;

  const affectedWidth =
    55;

  const findingWidth =
    width -
    idWidth -
    severityWidth -
    affectedWidth;


  function drawHeader() {

    ensureSpace(
      doc,
      40
    );


    const y =
      doc.y;


    doc.save();

    doc
      .roundedRect(
        left,
        y,
        width,
        30,
        4
      )
      .fill(
        COLORS.navy
      );

    doc.restore();


    doc
      .font(
        "Helvetica-Bold"
      )
      .fontSize(
        7.5
      )
      .fillColor(
        COLORS.white
      )
      .text(
        "ID",
        left +
          8,
        y +
          10,
        {
          width:
            idWidth -
            8,
        }
      );


    doc.text(
      "SEVERITY",
      left +
        idWidth,
      y +
        10,
      {
        width:
          severityWidth,
      }
    );


    doc.text(
      "FINDING",
      left +
        idWidth +
        severityWidth,
      y +
        10,
      {
        width:
          findingWidth,
      }
    );


    doc.text(
      "AFFECTED",
      left +
        width -
        affectedWidth,
      y +
        10,
      {
        width:
          affectedWidth -
          8,

        align:
          "right",
      }
    );


    doc.y =
      y +
      38;
  }


  drawHeader();


  grouped.forEach(
    (
      group,
      index
    ) => {

      const id =
        `WS-${String(
          index +
          1
        ).padStart(
          3,
          "0"
        )}`;


      const titleHeight =
        doc.heightOfString(
          group.title,
          {
            width:
              findingWidth -
              10,
          }
        );


      const rowHeight =
        Math.max(
          38,
          titleHeight +
            20
        );


      if (
        doc.y +
          rowHeight >
        contentBottom(
          doc
        )
      ) {
        doc.addPage();

        drawPageAccent(
          doc
        );

        drawHeader();
      }


      const y =
        doc.y;


      if (
        index %
          2 ===
        0
      ) {
        doc.save();

        doc
          .rect(
            left,
            y -
              3,
            width,
            rowHeight
          )
          .fill(
            COLORS.light
          );

        doc.restore();
      }


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          8
        )
        .fillColor(
          COLORS.blue
        )
        .text(
          id,
          left +
            8,
          y +
            8,
          {
            width:
              idWidth -
              8,
          }
        );


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          7.5
        )
        .fillColor(
          severityColor(
            group.severity
          )
        )
        .text(
          group.severity.toUpperCase(),
          left +
            idWidth,
          y +
            8,
          {
            width:
              severityWidth -
              6,
          }
        );


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          8.4
        )
        .fillColor(
          COLORS.navy
        )
        .text(
          group.title,
          left +
            idWidth +
            severityWidth,
          y +
            7,
          {
            width:
              findingWidth -
              10,
          }
        );


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          8.5
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          String(
            group.urls.length
          ),
          left +
            width -
            affectedWidth,
          y +
            8,
          {
            width:
              affectedWidth -
              8,

            align:
              "right",
          }
        );


      doc.y =
        y +
        rowHeight;
    }
  );
}


// ======================================================
// Regression Analysis
// ======================================================

function drawRegressionSection(
  doc,
  comparison
) {
  if (
    !comparison
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        9.5
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        "Regression information is not available for this assessment."
      );

    return;
  }


  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );

  const gap =
    12;

  const cardWidth =
    (
      width -
      gap *
        2
    ) /
    3;

  const y =
    doc.y;


  drawMetricCard(
    doc,
    left,
    y,
    cardWidth,
    76,
    "New",
    comparison.newCount ||
      0,
    "Introduced",
    COLORS.high
  );


  drawMetricCard(
    doc,
    left +
      cardWidth +
      gap,
    y,
    cardWidth,
    76,
    "Resolved",
    comparison.resolvedCount ||
      0,
    "No longer detected",
    COLORS.green
  );


  drawMetricCard(
    doc,
    left +
      (
        cardWidth +
        gap
      ) *
        2,
    y,
    cardWidth,
    76,
    "Unchanged",
    comparison.unchangedCount ||
      0,
    "Still present",
    COLORS.blue
  );


  doc.y =
    y +
    98;


  drawKeyValueRows(
    doc,
    [
      [
        "Comparison Status",

        comparison
          .hasPreviousScan
          ? "Compared with previous completed assessment"
          : "Baseline assessment",
      ],

      [
        "Previous Assessment",

        comparison
          .previousFinishedAt
          ? formatDate(
              comparison.previousFinishedAt
            )
          : "Not available",
      ],
    ]
  );


  if (
    comparison
      .newFindings
      ?.length >
    0
  ) {
    ensureSpace(
      doc,
      80
    );

    doc
      .font(
        "Helvetica-Bold"
      )
      .fontSize(
        10
      )
      .fillColor(
        COLORS.high
      )
      .text(
        "New Vulnerabilities"
      );

    doc.moveDown(
      0.45
    );


    for (
      const finding
      of comparison.newFindings
    ) {
      ensureSpace(
        doc,
        28
      );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(
          8.5
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          `• ${safeText(
            finding.title
          )} — ${safeText(
            finding.severity
          )}`
        );
    }
  }


  if (
    comparison
      .resolvedFindings
      ?.length >
    0
  ) {
    ensureSpace(
      doc,
      80
    );

    doc.moveDown(
      0.8
    );

    doc
      .font(
        "Helvetica-Bold"
      )
      .fontSize(
        10
      )
      .fillColor(
        COLORS.green
      )
      .text(
        "Resolved Vulnerabilities"
      );

    doc.moveDown(
      0.45
    );


    for (
      const finding
      of comparison.resolvedFindings
    ) {
      ensureSpace(
        doc,
        28
      );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(
          8.5
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          `• ${safeText(
            finding.title
          )} — ${safeText(
            finding.severity
          )}`
        );
    }
  }
}


// ======================================================
// Detailed Finding
// ======================================================

function drawFinding(
  doc,
  group,
  index
) {
  ensureSpace(
    doc,
    220
  );


  const left =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );

  const issueId =
    `WS-${String(
      index +
      1
    ).padStart(
      3,
      "0"
    )}`;


  const headerY =
    doc.y;


  doc.save();

  doc
    .roundedRect(
      left,
      headerY,
      width,
      72,
      8
    )
    .fillAndStroke(
      severityBackground(
        group.severity
      ),
      COLORS.border
    );

  doc.restore();


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      8
    )
    .fillColor(
      COLORS.blue
    )
    .text(
      issueId,
      left +
        14,
      headerY +
        12
    );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      13
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      group.title,
      left +
        14,
      headerY +
        28,
      {
        width:
          width -
          130,

        lineGap:
          2,
      }
    );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      8
    )
    .fillColor(
      severityColor(
        group.severity
      )
    )
    .text(
      group.severity.toUpperCase(),
      left +
        width -
        100,
      headerY +
        18,
      {
        width:
          85,

        align:
          "right",
      }
    );


  doc.y =
    headerY +
    90;


  drawKeyValueRows(
    doc,
    [
      [
        "Finding Code",
        group.code,
      ],

      [
        "OWASP Category",
        group.owasp,
      ],

      [
        "Confidence",
        group.confidence,
      ],

      [
        "Affected Locations",
        group.urls.length,
      ],

      [
        "Observed Instances",
        group.observations,
      ],
    ]
  );


  // ----------------------------------------------------
  // Affected Locations
  // ----------------------------------------------------

  ensureSpace(
    doc,
    80
  );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      10
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "Affected Locations"
    );


  doc.moveDown(
    0.45
  );


  if (
    group.urls.length ===
    0
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        8.5
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        "No specific URL was recorded."
      );

  } else {
    for (
      const url
      of group.urls
    ) {
      ensureSpace(
        doc,
        28
      );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(
          8.3
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          `• ${url}`,
          {
            lineGap:
              2,
          }
        );
    }
  }


  // ----------------------------------------------------
  // Evidence
  // ----------------------------------------------------

  ensureSpace(
    doc,
    100
  );


  doc.moveDown(
    0.8
  );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      10
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "Technical Evidence"
    );


  doc.moveDown(
    0.45
  );


  if (
    group.evidences.length ===
    0
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        8.8
      )
      .fillColor(
        COLORS.slate
      )
      .text(
        "No additional evidence was recorded."
      );

  } else {
    for (
      const evidence
      of group.evidences
    ) {
      ensureSpace(
        doc,
        42
      );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(
          8.8
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          `• ${evidence}`,
          {
            lineGap:
              3,
          }
        );
    }
  }


  // ----------------------------------------------------
  // Remediation Box
  // ----------------------------------------------------

  doc.moveDown(
    0.9
  );


  const remediation =
    safeText(
      group.remediation
    );


  const remediationHeight =
    doc.heightOfString(
      remediation,
      {
        width:
          width -
          32,

        lineGap:
          3,
      }
    ) +
    48;


  ensureSpace(
    doc,
    remediationHeight +
      25
  );


  const remediationY =
    doc.y;


  doc.save();

  doc
    .roundedRect(
      left,
      remediationY,
      width,
      remediationHeight,
      7
    )
    .fillAndStroke(
      COLORS.greenSoft,
      "#A7F3D0"
    );

  doc.restore();


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      8
    )
    .fillColor(
      COLORS.green
    )
    .text(
      "RECOMMENDED REMEDIATION",
      left +
        16,
      remediationY +
        14,
      {
        width:
          width -
          32,
      }
    );


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      8.8
    )
    .fillColor(
      COLORS.slate
    )
    .text(
      remediation,
      left +
        16,
      remediationY +
        32,
      {
        width:
          width -
          32,

        lineGap:
          3,
      }
    );


  doc.y =
    remediationY +
    remediationHeight +
    28;
}


// ======================================================
// Cover Page
// ======================================================

function drawCover(
  doc,
  scan,
  user,
  score,
  grouped
) {
  const pageWidth =
    doc.page.width;

  const pageHeight =
    doc.page.height;

  const margin =
    doc.page.margins.left;

  const width =
    contentWidth(
      doc
    );

  const rating =
    securityRating(
      score
    );


  // ----------------------------------------------------
  // Header Block
  // ----------------------------------------------------

  doc.save();

  doc
    .rect(
      0,
      0,
      pageWidth,
      210
    )
    .fill(
      COLORS.navy
    );

  doc
    .rect(
      0,
      210,
      pageWidth,
      7
    )
    .fill(
      COLORS.blue
    );

  doc.restore();


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      29
    )
    .fillColor(
      COLORS.white
    )
    .text(
      "WebShield",
      margin,
      58,
      {
        width,
      }
    );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      14
    )
    .fillColor(
      "#BFDBFE"
    )
    .text(
      "WEB APPLICATION SECURITY ASSESSMENT",
      margin,
      103,
      {
        width,
      }
    );


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      9
    )
    .fillColor(
      "#CBD5E1"
    )
    .text(
      "OWASP-focused automated vulnerability assessment",
      margin,
      131,
      {
        width,
      }
    );


  doc.save();

  doc
    .roundedRect(
      pageWidth -
        margin -
        100,
      54,
      100,
      27,
      5
    )
    .fill(
      COLORS.navySoft
    );

  doc.restore();


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      7.5
    )
    .fillColor(
      COLORS.white
    )
    .text(
      "CONFIDENTIAL",
      pageWidth -
        margin -
        100,
      64,
      {
        width:
          100,

        align:
          "center",
      }
    );


  // ----------------------------------------------------
  // Score
  // ----------------------------------------------------

  const scoreY =
    260;

  const scoreWidth =
    170;


  doc.save();

  doc
    .roundedRect(
      margin,
      scoreY,
      scoreWidth,
      128,
      10
    )
    .fillAndStroke(
      COLORS.light,
      COLORS.border
    );

  doc.restore();


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      8
    )
    .fillColor(
      COLORS.muted
    )
    .text(
      "SECURITY POSTURE",
      margin +
        18,
      scoreY +
        18,
      {
        width:
          scoreWidth -
          36,
      }
    );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      32
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      `${score}/100`,
      margin +
        18,
      scoreY +
        42,
      {
        width:
          scoreWidth -
          36,
      }
    );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      10
    )
    .fillColor(
      rating.color
    )
    .text(
      rating.label.toUpperCase(),
      margin +
        18,
      scoreY +
        91,
      {
        width:
          scoreWidth -
          36,
      }
    );


  // ----------------------------------------------------
  // Metadata
  // ----------------------------------------------------

  const metaX =
    margin +
    scoreWidth +
    28;

  const metaWidth =
    width -
    scoreWidth -
    28;


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      11
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "Assessment Details",
      metaX,
      scoreY +
        2,
      {
        width:
          metaWidth,
      }
    );


  const metadata = [
    [
      "Target",
      scan.url,
    ],

    [
      "Assessment ID",
      scan._id,
    ],

    [
      "Status",
      scan.status,
    ],

    [
      "Completed",
      formatDate(
        scan.finishedAt
      ),
    ],

    [
      "Prepared For",
      user.email,
    ],
  ];


  let metaY =
    scoreY +
    29;


  for (
    const [
      label,
      value,
    ]
    of metadata
  ) {
    doc
      .font(
        "Helvetica-Bold"
      )
      .fontSize(
        7
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        label.toUpperCase(),
        metaX,
        metaY,
        {
          width:
            85,
        }
      );


    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        8.3
      )
      .fillColor(
        COLORS.slate
      )
      .text(
        safeText(
          value
        ),
        metaX +
          88,
        metaY,
        {
          width:
            metaWidth -
            88,

          lineGap:
            1,
        }
      );


    metaY +=
      22;
  }


  // ----------------------------------------------------
  // Overview
  // ----------------------------------------------------

  const overviewY =
    435;


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      11
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "Report Overview",
      margin,
      overviewY,
      {
        width,
      }
    );


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      9
    )
    .fillColor(
      COLORS.slate
    )
    .text(
      "This report presents the assessment scope, security posture, " +
        "prioritized vulnerabilities, regression status, technical evidence " +
        "and recommended remediation actions.",
      margin,
      overviewY +
        25,
      {
        width,
        lineGap:
          3,
      }
    );


  // ----------------------------------------------------
  // Bottom Metrics
  // ----------------------------------------------------

  const metricY =
    overviewY +
    90;

  const gap =
    10;

  const metricWidth =
    (
      width -
      gap *
        2
    ) /
    3;


  drawMetricCard(
    doc,
    margin,
    metricY,
    metricWidth,
    78,
    "Observations",
    scan.findings
      ?.length ||
      0,
    "Detected instances",
    COLORS.blue
  );


  drawMetricCard(
    doc,
    margin +
      metricWidth +
      gap,
    metricY,
    metricWidth,
    78,
    "Unique Issues",
    grouped.length,
    "Grouped by root finding",
    COLORS.medium
  );


  drawMetricCard(
    doc,
    margin +
      (
        metricWidth +
        gap
      ) *
        2,
    metricY,
    metricWidth,
    78,
    "Pages Assessed",
    scan.pages
      ?.length ||
      scan.summary
        ?.pages ||
      0,
    "Discovered pages",
    COLORS.green
  );


  // ----------------------------------------------------
  // Disclaimer
  // ----------------------------------------------------

  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      8
    )
    .fillColor(
      COLORS.muted
    )
    .text(
      "Authorized automated assessment only. Results may contain false positives " +
        "or false negatives and should be validated before remediation decisions.",
      margin,
      pageHeight -
        100,
      {
        width,
        align:
          "center",
        lineGap:
          2,
      }
    );
}


// ======================================================
// Footer
//
// Important:
// Temporarily removes bottom margin so writing footer
// does NOT create extra PDF pages.
// ======================================================

function addFooters(
  doc
) {
  const range =
    doc.bufferedPageRange();


  for (
    let pageIndex =
      range.start;
    pageIndex <
      range.start +
        range.count;
    pageIndex +=
      1
  ) {
    doc.switchToPage(
      pageIndex
    );


    const savedX =
      doc.x;

    const savedY =
      doc.y;

    const savedBottom =
      doc.page.margins.bottom;


    doc.page.margins.bottom =
      0;


    const left =
      doc.page.margins.left;

    const width =
      contentWidth(
        doc
      );

    const footerLineY =
      doc.page.height -
      45;

    const footerTextY =
      doc.page.height -
      32;


    doc.save();

    doc
      .moveTo(
        left,
        footerLineY
      )
      .lineTo(
        left +
          width,
        footerLineY
      )
      .lineWidth(
        0.4
      )
      .strokeColor(
        COLORS.border
      )
      .stroke();

    doc.restore();


    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        7
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        pageIndex ===
          range.start
          ? "WebShield · Confidential Security Assessment"
          : "WebShield · Web Application Security Assessment",
        left,
        footerTextY,
        {
          width:
            width *
            0.7,

          lineBreak:
            false,
        }
      );


    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        7
      )
      .fillColor(
        COLORS.muted
      )
      .text(
        `Page ${
          pageIndex -
          range.start +
          1
        } of ${
          range.count
        }`,
        left +
          width *
            0.7,
        footerTextY,
        {
          width:
            width *
            0.3,

          align:
            "right",

          lineBreak:
            false,
        }
      );


    doc.page.margins.bottom =
      savedBottom;

    doc.x =
      savedX;

    doc.y =
      savedY;
  }
}


// ======================================================
// Main Report Generator
// ======================================================

export function generateProfessionalReport(
  scan,
  user,
  res
) {
  const doc =
    new PDFDocument({
      size: "A4",

      margin: 48,

      bufferPages: true,

      info: {
        Title:
          "WebShield Security Assessment Report",

        Author:
          "WebShield",

        Subject:
          `Security assessment for ${scan.url}`,

        Keywords:
          "WebShield, OWASP, vulnerability assessment, security report",
      },
    });


  const findings =
    scan.findings ||
    [];


  const groupedFindings =
    groupFindings(
      findings
    );


  const severityCounts =
    buildSeverityCounts(
      findings
    );


  const owaspSummary =
    buildOwaspSummary(
      findings
    );


  const securityScore =
    Number.isFinite(
      Number(
        scan.securityScore
      )
    )
      ? Number(
          scan.securityScore
        )
      : 100;


  const highImpact =
    severityCounts.Critical +
    severityCounts.High;


  const filename =
    `webshield-security-assessment-${scan._id}.pdf`;


  res.setHeader(
    "Content-Type",
    "application/pdf"
  );


  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${filename}"`
  );


  doc.pipe(
    res
  );


  // ====================================================
  // Cover Page
  // ====================================================

  drawCover(
    doc,
    scan,
    user,
    securityScore,
    groupedFindings
  );


  // ====================================================
  // 01 Executive Summary
  // ====================================================

  doc.addPage();

  drawPageAccent(
    doc
  );


  drawSectionHeader(
    doc,
    1,
    "Executive Summary",
    "Management-level overview of the current application security posture."
  );


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      9.8
    )
    .fillColor(
      COLORS.slate
    )
    .text(
      buildExecutiveSummary(
        findings,
        groupedFindings,
        severityCounts
      ),
      {
        width:
          contentWidth(
            doc
          ),

        lineGap:
          4,
      }
    );


  doc.moveDown(
    1.3
  );


  const metricsY =
    doc.y;

  const metricGap =
    9;

  const metricWidth =
    (
      contentWidth(
        doc
      ) -
      metricGap *
        3
    ) /
    4;


  const rating =
    securityRating(
      securityScore
    );


  drawMetricCard(
    doc,
    doc.page.margins.left,
    metricsY,
    metricWidth,
    80,
    "Security Score",
    `${securityScore}/100`,
    rating.label,
    rating.color
  );


  drawMetricCard(
    doc,
    doc.page.margins.left +
      metricWidth +
      metricGap,
    metricsY,
    metricWidth,
    80,
    "Observations",
    findings.length,
    "Detected instances",
    COLORS.blue
  );


  drawMetricCard(
    doc,
    doc.page.margins.left +
      (
        metricWidth +
        metricGap
      ) *
        2,
    metricsY,
    metricWidth,
    80,
    "Unique Issues",
    groupedFindings.length,
    "Grouped issues",
    COLORS.medium
  );


  drawMetricCard(
    doc,
    doc.page.margins.left +
      (
        metricWidth +
        metricGap
      ) *
        3,
    metricsY,
    metricWidth,
    80,
    "High Impact",
    highImpact,
    "Critical + High",
    COLORS.high
  );


  doc.y =
    metricsY +
    103;


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      10
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "Severity Distribution"
    );


  doc.moveDown(
    0.6
  );


  drawSeverityStrip(
    doc,
    severityCounts
  );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      10
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "Assessment Snapshot"
    );


  doc.moveDown(
    0.5
  );


  drawKeyValueRows(
    doc,
    [
      [
        "Target",
        scan.url,
      ],

      [
        "Assessment Window",
        `${formatDate(
          scan.startedAt
        )} — ${formatDate(
          scan.finishedAt
        )}`,
      ],

      [
        "Pages Discovered",
        scan.pages
          ?.length ||
          scan.summary
            ?.pages ||
          0,
      ],

      [
        "Forms Discovered",
        scan.discovery
          ?.forms
          ?.length ||
          scan.summary
            ?.forms ||
          0,
      ],

      [
        "API Requests Observed",
        scan.discovery
          ?.apiRequests
          ?.length ||
          scan.summary
            ?.apiRequests ||
          0,
      ],
    ]
  );


  // ====================================================
  // 02 Risk & OWASP
  // ====================================================

  doc.addPage();

  drawPageAccent(
    doc
  );


  drawSectionHeader(
    doc,
    2,
    "Risk and OWASP Overview",
    "Distribution of security observations across OWASP categories."
  );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      10
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "OWASP Category Distribution"
    );


  doc.moveDown(
    0.6
  );


  drawOwaspTable(
    doc,
    owaspSummary
  );


  doc.moveDown(
    1.3
  );


  ensureSpace(
    doc,
    100
  );


  doc
    .font(
      "Helvetica-Bold"
    )
    .fontSize(
      10
    )
    .fillColor(
      COLORS.navy
    )
    .text(
      "Risk Interpretation"
    );


  doc.moveDown(
    0.5
  );


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      9
    )
    .fillColor(
      COLORS.slate
    )
    .text(
      "Repeated observations are consolidated into unique issue types in this " +
        "report. This allows remediation teams to address the root cause of a " +
        "security weakness once, while still showing every affected location.",
      {
        lineGap:
          3,
      }
    );


  // ====================================================
  // 03 Prioritized Findings
  // ====================================================

  doc.moveDown(
    1.4
  );


  drawSectionHeader(
    doc,
    3,
    "Prioritized Findings",
    "Unique issue types ranked by severity. The affected count represents distinct application locations."
  );


  drawFindingsOverviewTable(
    doc,
    groupedFindings
  );


  // ====================================================
  // 04 Scope and Discovery
  // ====================================================

  doc.addPage();

  drawPageAccent(
    doc
  );


  drawSectionHeader(
    doc,
    4,
    "Assessment Scope and Discovery",
    "Application surface discovered using passive crawling and browser-based dynamic analysis."
  );


  const inputCount =
    scan.discovery
      ?.forms
      ?.reduce(
        (
          total,
          form
        ) =>
          total +
          (
            form.inputs
              ?.length ||
            0
          ),
        0
      ) ||
    0;


  const discoveryY =
    doc.y;


  const discoveryGap =
    9;


  const discoveryWidth =
    (
      contentWidth(
        doc
      ) -
      discoveryGap *
        3
    ) /
    4;


  drawMetricCard(
    doc,
    doc.page.margins.left,
    discoveryY,
    discoveryWidth,
    76,
    "Pages",
    scan.pages
      ?.length ||
      0,
    "Discovered",
    COLORS.blue
  );


  drawMetricCard(
    doc,
    doc.page.margins.left +
      discoveryWidth +
      discoveryGap,
    discoveryY,
    discoveryWidth,
    76,
    "Forms",
    scan.discovery
      ?.forms
      ?.length ||
      0,
    "Discovered",
    COLORS.green
  );


  drawMetricCard(
    doc,
    doc.page.margins.left +
      (
        discoveryWidth +
        discoveryGap
      ) *
        2,
    discoveryY,
    discoveryWidth,
    76,
    "Inputs",
    inputCount,
    "Form fields",
    COLORS.medium
  );


  drawMetricCard(
    doc,
    doc.page.margins.left +
      (
        discoveryWidth +
        discoveryGap
      ) *
        3,
    discoveryY,
    discoveryWidth,
    76,
    "API Requests",
    scan.discovery
      ?.apiRequests
      ?.length ||
      0,
    "Observed",
    COLORS.high
  );


  doc.y =
    discoveryY +
    100;


  if (
    scan.pages
      ?.length >
    0
  ) {
    doc
      .font(
        "Helvetica-Bold"
      )
      .fontSize(
        10
      )
      .fillColor(
        COLORS.navy
      )
      .text(
        "Discovered Pages"
      );


    doc.moveDown(
      0.5
    );


    for (
      const page
      of scan.pages
    ) {
      ensureSpace(
        doc,
        28
      );

      doc
        .font(
          "Helvetica"
        )
        .fontSize(
          8.5
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          `• ${page}`
        );
    }
  }


  // ====================================================
  // 05 Regression
  // ====================================================

  doc.moveDown(
    1.3
  );


  drawSectionHeader(
    doc,
    5,
    "Regression Analysis",
    "Comparison with the previous completed assessment of the same target."
  );


  drawRegressionSection(
    doc,
    scan.comparison
  );


  // ====================================================
  // 06 Detailed Findings
  // ====================================================

  doc.addPage();

  drawPageAccent(
    doc
  );


  drawSectionHeader(
    doc,
    6,
    "Detailed Security Findings",
    "Technical details are grouped by finding type to eliminate repetitive scanner output."
  );


  if (
    groupedFindings.length ===
    0
  ) {
    doc
      .font(
        "Helvetica"
      )
      .fontSize(
        9.5
      )
      .fillColor(
        COLORS.slate
      )
      .text(
        "No security findings were recorded during this assessment."
      );

  } else {
    groupedFindings.forEach(
      (
        group,
        index
      ) => {

        drawFinding(
          doc,
          group,
          index
        );

      }
    );
  }


  // ====================================================
  // 07 Methodology
  // ====================================================

  doc.addPage();

  drawPageAccent(
    doc
  );


  drawSectionHeader(
    doc,
    7,
    "Assessment Methodology",
    "Automated security assessment workflow performed by WebShield."
  );


  const methodology = [
    "Authorized target validation and scanning scope enforcement.",

    "Passive HTTP response analysis and security-header inspection.",

    "Same-origin application crawling and route discovery.",

    "Dynamic browser-based analysis using Playwright.",

    "Form, input and observed API request discovery.",

    "Controlled active checks for supported vulnerability classes.",

    "OWASP category mapping and severity classification.",

    "Security score calculation based on detected severity.",

    "Regression analysis against the previous completed assessment where available.",
  ];


  methodology.forEach(
    (
      item,
      index
    ) => {

      ensureSpace(
        doc,
        45
      );


      const y =
        doc.y;


      doc.save();

      doc
        .circle(
          doc.page.margins.left +
            11,
          y +
            11,
          10
        )
        .fill(
          COLORS.blueSoft
        );

      doc.restore();


      doc
        .font(
          "Helvetica-Bold"
        )
        .fontSize(
          8
        )
        .fillColor(
          COLORS.blue
        )
        .text(
          String(
            index +
            1
          ),
          doc.page.margins.left +
            5,
          y +
            7,
          {
            width:
              12,

            align:
              "center",
          }
        );


      doc
        .font(
          "Helvetica"
        )
        .fontSize(
          9
        )
        .fillColor(
          COLORS.slate
        )
        .text(
          item,
          doc.page.margins.left +
            35,
          y +
            3,
          {
            width:
              contentWidth(
                doc
              ) -
              35,

            lineGap:
              3,
          }
        );


      doc.y =
        Math.max(
          doc.y,
          y +
            36
        );
    }
  );


  // ====================================================
  // 08 Scope & Limitations
  // ====================================================

  doc.moveDown(
    1
  );


  drawSectionHeader(
    doc,
    8,
    "Scope and Limitations",
    "Important context for interpretation of automated security results."
  );


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      9.2
    )
    .fillColor(
      COLORS.slate
    )
    .text(
      "WebShield is an automated vulnerability assessment platform. Findings " +
        "represent issues detected by the enabled scanner modules during the " +
        "assessment window. Automated scanning can produce false positives and " +
        "false negatives and does not provide the same coverage as a complete " +
        "manual penetration test.",
      {
        lineGap:
          4,
      }
    );


  doc.moveDown(
    0.9
  );


  doc
    .font(
      "Helvetica"
    )
    .fontSize(
      9.2
    )
    .fillColor(
      COLORS.slate
    )
    .text(
      "Security testing must only be performed against applications and systems " +
        "for which explicit authorization has been granted. This WebShield " +
        "deployment restricts active assessment to the controlled laboratory target.",
      {
        lineGap:
          4,
      }
    );


  // ====================================================
  // Footer
  // ====================================================

  addFooters(
    doc
  );


  // ====================================================
  // Finish
  // ====================================================

  doc.end();
}