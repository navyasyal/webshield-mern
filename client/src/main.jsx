import React, {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  createRoot,
} from "react-dom/client";

import {
  io,
} from "socket.io-client";

import {
  Shield,
  ScanSearch,
  History,
  LogOut,
  Download,
  Activity,
  ArrowLeft,
  Search,
  Filter,
  Eye,
  EyeOff,
  ShieldCheck,
  LockKeyhole,
  Radar,
  CheckCircle2,
  Sparkles,
  Gauge,
  PieChart,
  TrendingUp,
  AlertTriangle,
  BarChart3,
  CalendarDays,
  SlidersHorizontal,
  ArrowUpDown,
  ExternalLink,
  RotateCcw,
} from "lucide-react";

import "./style.css";
import "./analytics.css";
import "./history.css";


// ======================================================
// API
// ======================================================

async function api(
  path,
  options = {}
) {
  const response =
    await fetch(
      "/api" + path,
      {
        credentials:
          "same-origin",

        headers: {
          "Content-Type":
            "application/json",
        },

        ...options,
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error ||
      "Request failed"
    );
  }

  return data;
}


// ======================================================
// Helpers
// ======================================================

function getRiskRating(
  score
) {
  if (
    score === null ||
    score === undefined
  ) {
    return {
      label:
        "No Assessment",

      className:
        "good",

      description:
        "Run your first completed scan to calculate the security posture.",

      color:
        "#94a3b8",
    };
  }

  if (
    score >= 90
  ) {
    return {
      label:
        "Strong",

      className:
        "strong",

      description:
        "The latest assessment indicates a strong overall security posture.",

      color:
        "#059669",
    };
  }

  if (
    score >= 75
  ) {
    return {
      label:
        "Good",

      className:
        "good",

      description:
        "Security posture is good, with some findings requiring remediation.",

      color:
        "#2563eb",
    };
  }

  if (
    score >= 50
  ) {
    return {
      label:
        "Needs Improvement",

      className:
        "warning",

      description:
        "Several security weaknesses should be prioritized for remediation.",

      color:
        "#d97706",
    };
  }

  return {
    label:
      "High Risk",

    className:
      "danger",

    description:
      "High-impact vulnerabilities are significantly reducing the security score.",

    color:
      "#dc2626",
  };
}


function buildSeverityGradient(
  counts
) {
  const values = [
    {
      count:
        counts.Critical,

      color:
        "#7f1d1d",
    },

    {
      count:
        counts.High,

      color:
        "#dc2626",
    },

    {
      count:
        counts.Medium,

      color:
        "#f59e0b",
    },

    {
      count:
        counts.Low,

      color:
        "#3b82f6",
    },

    {
      count:
        counts.Info,

      color:
        "#94a3b8",
    },
  ];

  const total =
    values.reduce(
      (
        sum,
        item
      ) =>
        sum +
        item.count,

      0
    );

  if (
    total === 0
  ) {
    return (
      "conic-gradient(#e2e8f0 0deg 360deg)"
    );
  }

  let current =
    0;

  const segments =
    values
      .filter(
        (
          item
        ) =>
          item.count >
          0
      )
      .map(
        (
          item
        ) => {

          const start =
            current;

          current +=
            (
              item.count /
              total
            ) *
            360;

          return (
            `${item.color} ${start}deg ${current}deg`
          );

        }
      );

  return (
    `conic-gradient(${segments.join(", ")})`
  );
}


function formatScanDate(
  value
) {
  if (
    !value
  ) {
    return "Not available";
  }

  const date =
    new Date(
      value
    );

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "Not available";
  }

  return date.toLocaleString(
    "en-IN",
    {
      day:
        "2-digit",

      month:
        "short",

      year:
        "numeric",

      hour:
        "2-digit",

      minute:
        "2-digit",
    }
  );
}


function getScanSeverityCounts(
  scan
) {
  const counts = {
    Critical:
      0,

    High:
      0,

    Medium:
      0,

    Low:
      0,

    Info:
      0,
  };

  for (
    const finding
    of scan.findings ||
    []
  ) {
    const severity =
      finding.severity ||
      "Info";

    if (
      Object.prototype
        .hasOwnProperty
        .call(
          counts,
          severity
        )
    ) {
      counts[
        severity
      ] += 1;

    } else {
      counts.Info +=
        1;
    }
  }

  return counts;
}


// ======================================================
// App
// ======================================================

function App() {

  // ====================================================
  // Authentication
  // ====================================================

  const [
    user,
    setUser,
  ] = useState(null);


  const [
    mode,
    setMode,
  ] = useState(
    "login"
  );


  const [
    email,
    setEmail,
  ] = useState("");


  const [
    password,
    setPassword,
  ] = useState("");


  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState("");


  const [
    showPassword,
    setShowPassword,
  ] = useState(false);


  const [
    showConfirmPassword,
    setShowConfirmPassword,
  ] = useState(false);


  // ====================================================
  // UI
  // ====================================================

  const [
    activeView,
    setActiveView,
  ] = useState(
    "dashboard"
  );


  const [
    error,
    setError,
  ] = useState("");


  const [
    busy,
    setBusy,
  ] = useState(false);


  // ====================================================
  // Scan Detail Scroll
  // ====================================================

  const scanDetailsRef =
    useRef(null);


  const [
    scrollRequest,
    setScrollRequest,
  ] = useState(0);


  // ====================================================
  // Scanner
  // ====================================================

  const [
    url,
    setUrl,
  ] = useState(
    "http://lab:4000/"
  );


  const [
    authorized,
    setAuthorized,
  ] = useState(false);


  const [
    scans,
    setScans,
  ] = useState([]);


  const [
    selected,
    setSelected,
  ] = useState(null);


  const [
    liveProgress,
    setLiveProgress,
  ] = useState(null);


  // ====================================================
  // Finding Filters
  // ====================================================

  const [
    findingSearch,
    setFindingSearch,
  ] = useState("");


  const [
    severityFilter,
    setSeverityFilter,
  ] = useState(
    "All"
  );


  const [
    owaspFilter,
    setOwaspFilter,
  ] = useState(
    "All"
  );


  // ====================================================
  // History Filters
  // ====================================================

  const [
    historySearch,
    setHistorySearch,
  ] = useState("");


  const [
    historyStatus,
    setHistoryStatus,
  ] = useState(
    "All"
  );


  const [
    historySort,
    setHistorySort,
  ] = useState(
    "newest"
  );


  // ====================================================
  // Password Checks
  // ====================================================

  const passwordChecks =
    useMemo(
      () => ({
        length:
          password.length >=
          8,

        letter:
          /[A-Za-z]/.test(
            password
          ),

        number:
          /\d/.test(
            password
          ),
      }),

      [
        password,
      ]
    );


  // ====================================================
  // Load
  // ====================================================

  async function load() {

    try {

      const currentUser =
        await api(
          "/me"
        );


      const scanList =
        await api(
          "/scans"
        );


      setUser(
        currentUser
      );


      setScans(
        scanList
      );

    } catch {

      setUser(
        null
      );

    }
  }


  useEffect(
    () => {

      load();

    },
    []
  );


  // ====================================================
  // Active Scan Detection
  // ====================================================

  const hasActiveScans =
    scans.some(
      (
        scan
      ) =>
        scan.status ===
          "queued" ||
        scan.status ===
          "running"
    );


  // ====================================================
  // Poll Running Scans
  // ====================================================

  useEffect(
    () => {

      if (
        !user ||
        !hasActiveScans
      ) {
        return;
      }


      const refreshScans =
        async () => {

          try {

            const items =
              await api(
                "/scans"
              );


            setScans(
              items
            );


            if (
              selected?._id
            ) {

              const current =
                items.find(
                  (
                    scan
                  ) =>
                    scan._id ===
                    selected._id
                );


              if (
                current
              ) {
                setSelected(
                  current
                );
              }
            }

          } catch {

            // Ignore temporary polling failures.

          }
        };


      const timer =
        setInterval(
          refreshScans,
          4000
        );


      return () => {

        clearInterval(
          timer
        );

      };

    },

    [
      user,
      hasActiveScans,
      selected?._id,
    ]
  );


  // ====================================================
  // Smooth Scan Detail Scroll
  // ====================================================

  useEffect(
    () => {

      if (
        scrollRequest ===
          0 ||
        activeView !==
          "history" ||
        !selected?._id
      ) {
        return;
      }


      const timer =
        window.setTimeout(
          () => {

            scanDetailsRef
              .current
              ?.scrollIntoView({
                behavior:
                  "smooth",

                block:
                  "start",
              });

          },
          120
        );


      return () => {

        window.clearTimeout(
          timer
        );

      };

    },

    [
      scrollRequest,
      activeView,
      selected?._id,
    ]
  );


  // ====================================================
  // Socket.IO
  // ====================================================

  useEffect(
    () => {

      if (
        !user
      ) {
        return;
      }


      const socket =
        io({
          path:
            "/socket.io",

          withCredentials:
            true,

          transports: [
            "websocket",
            "polling",
          ],
        });


      socket.on(
        "scan:progress",

        async (
          event
        ) => {

          setLiveProgress(
            event
          );


          setScans(
            (
              currentScans
            ) =>
              currentScans.map(
                (
                  scan
                ) =>
                  scan._id ===
                  event.scanId
                    ? {
                        ...scan,

                        status:
                          event.status,

                        progress: {
                          percent:
                            event.percent,

                          stage:
                            event.stage,

                          message:
                            event.message,
                        },
                      }
                    : scan
              )
          );


          setSelected(
            (
              current
            ) => {

              if (
                !current ||
                current._id !==
                event.scanId
              ) {
                return current;
              }


              return {
                ...current,

                status:
                  event.status,

                progress: {
                  percent:
                    event.percent,

                  stage:
                    event.stage,

                  message:
                    event.message,
                },
              };

            }
          );


          if (
            event.status ===
              "completed" ||
            event.status ===
              "failed"
          ) {

            try {

              const finalScan =
                await api(
                  "/scans/" +
                  event.scanId
                );


              setScans(
                (
                  currentScans
                ) =>
                  currentScans.map(
                    (
                      scan
                    ) =>
                      scan._id ===
                      event.scanId
                        ? finalScan
                        : scan
                  )
              );


              setSelected(
                (
                  current
                ) =>
                  current?._id ===
                  event.scanId
                    ? finalScan
                    : current
              );

            } catch (
              refreshError
            ) {

              console.error(
                "Final scan refresh failed:",
                refreshError.message
              );

            }
          }

        }
      );


      return () => {

        socket.disconnect();

      };

    },

    [
      user,
    ]
  );


  // ====================================================
  // Authentication
  // ====================================================

  function switchAuthMode(
    nextMode
  ) {

    setMode(
      nextMode
    );

    setError(
      ""
    );

    setPassword(
      ""
    );

    setConfirmPassword(
      ""
    );

    setShowPassword(
      false
    );

    setShowConfirmPassword(
      false
    );
  }


  async function submitAuth(
    event
  ) {

    event.preventDefault();

    setError(
      ""
    );


    if (
      mode ===
        "register" &&
      password !==
        confirmPassword
    ) {

      setError(
        "Passwords do not match."
      );

      return;
    }


    if (
      mode ===
        "register" &&
      !passwordChecks.length
    ) {

      setError(
        "Password must contain at least 8 characters."
      );

      return;
    }


    setBusy(
      true
    );


    try {

      await api(
        "/auth/" +
        mode,

        {
          method:
            "POST",

          body:
            JSON.stringify({
              email,
              password,
            }),
        }
      );


      setPassword(
        ""
      );

      setConfirmPassword(
        ""
      );


      await load();

    } catch (
      authError
    ) {

      setError(
        authError.message
      );

    } finally {

      setBusy(
        false
      );

    }
  }


  // ====================================================
  // Start Scan
  // ====================================================

  async function start(
    event
  ) {

    event.preventDefault();

    setBusy(
      true
    );

    setError(
      ""
    );

    setLiveProgress(
      null
    );


    try {

      const result =
        await api(
          "/scans",

          {
            method:
              "POST",

            body:
              JSON.stringify({
                url,
                authorized,
              }),
          }
        );


      const scan =
        await api(
          "/scans/" +
          result.id
        );


      openScan(
        scan
      );


      setActiveView(
        "history"
      );


      setScans(
        await api(
          "/scans"
        )
      );

    } catch (
      scanError
    ) {

      setError(
        scanError.message
      );

    } finally {

      setBusy(
        false
      );

    }
  }


  // ====================================================
  // Open / Close
  // ====================================================

  function openScan(
    scan
  ) {

    setSelected(
      scan
    );

    setFindingSearch(
      ""
    );

    setSeverityFilter(
      "All"
    );

    setOwaspFilter(
      "All"
    );

    setScrollRequest(
      (
        current
      ) =>
        current +
        1
    );
  }


  function closeScan() {

    setSelected(
      null
    );

    setFindingSearch(
      ""
    );

    setSeverityFilter(
      "All"
    );

    setOwaspFilter(
      "All"
    );
  }


  // ====================================================
  // Logout
  // ====================================================

  async function logout() {

    await api(
      "/auth/logout",

      {
        method:
          "POST",
      }
    );


    setUser(
      null
    );

    setSelected(
      null
    );

    setLiveProgress(
      null
    );

    setActiveView(
      "dashboard"
    );
  }


  // ====================================================
  // Global Analytics
  // ====================================================

  const allFindings =
    useMemo(
      () =>
        scans.flatMap(
          (
            scan
          ) =>
            scan.findings ||
            []
        ),

      [
        scans,
      ]
    );


  const severityCounts =
    useMemo(
      () => {

        const counts = {
          Critical:
            0,

          High:
            0,

          Medium:
            0,

          Low:
            0,

          Info:
            0,
        };


        for (
          const finding
          of allFindings
        ) {

          const severity =
            finding.severity ||
            "Info";


          if (
            Object.prototype
              .hasOwnProperty
              .call(
                counts,
                severity
              )
          ) {
            counts[
              severity
            ] += 1;

          } else {
            counts.Info +=
              1;
          }
        }


        return counts;

      },

      [
        allFindings,
      ]
    );


  const completedScanItems =
    useMemo(
      () =>
        scans.filter(
          (
            scan
          ) =>
            scan.status ===
            "completed"
        ),

      [
        scans,
      ]
    );


  const completedScans =
    completedScanItems.length;


  const runningScans =
    scans.filter(
      (
        scan
      ) =>
        scan.status ===
          "running" ||
        scan.status ===
          "queued"
    ).length;


  const totalFindings =
    allFindings.length;


  const highSeverity =
    severityCounts.High +
    severityCounts.Critical;


  const latestCompletedScan =
    completedScanItems[
      0
    ] ||
    null;


  const latestSecurityScore =
    latestCompletedScan &&
    Number.isFinite(
      Number(
        latestCompletedScan.securityScore
      )
    )
      ? Number(
          latestCompletedScan.securityScore
        )
      : null;


  const averageSecurityScore =
    useMemo(
      () => {

        const scores =
          completedScanItems
            .map(
              (
                scan
              ) =>
                Number(
                  scan.securityScore
                )
            )
            .filter(
              (
                value
              ) =>
                Number.isFinite(
                  value
                )
            );


        if (
          scores.length ===
          0
        ) {
          return null;
        }


        return Math.round(
          scores.reduce(
            (
              sum,
              value
            ) =>
              sum +
              value,

            0
          ) /
          scores.length
        );

      },

      [
        completedScanItems,
      ]
    );


  const riskRating =
    getRiskRating(
      latestSecurityScore
    );


  const severityGradient =
    useMemo(
      () =>
        buildSeverityGradient(
          severityCounts
        ),

      [
        severityCounts,
      ]
    );


  const recentTrendScans =
    useMemo(
      () =>
        completedScanItems
          .slice(
            0,
            7
          )
          .reverse(),

      [
        completedScanItems,
      ]
    );


  // ====================================================
  // Professional History Data
  // ====================================================

  const filteredHistoryScans =
    useMemo(
      () => {

        const query =
          historySearch
            .trim()
            .toLowerCase();


        const filtered =
          scans.filter(
            (
              scan
            ) => {

              const matchesSearch =
                !query ||
                String(
                  scan.url ||
                  ""
                )
                  .toLowerCase()
                  .includes(
                    query
                  );


              const matchesStatus =
                historyStatus ===
                  "All" ||
                scan.status ===
                  historyStatus;


              return (
                matchesSearch &&
                matchesStatus
              );

            }
          );


        return [
          ...filtered,
        ].sort(
          (
            first,
            second
          ) => {

            const firstDate =
              new Date(
                first.createdAt ||
                first.startedAt ||
                0
              ).getTime();


            const secondDate =
              new Date(
                second.createdAt ||
                second.startedAt ||
                0
              ).getTime();


            if (
              historySort ===
              "oldest"
            ) {
              return (
                firstDate -
                secondDate
              );
            }


            if (
              historySort ===
              "score-high"
            ) {
              return (
                Number(
                  second.securityScore ??
                  -1
                ) -
                Number(
                  first.securityScore ??
                  -1
                )
              );
            }


            if (
              historySort ===
              "score-low"
            ) {
              return (
                Number(
                  first.securityScore ??
                  101
                ) -
                Number(
                  second.securityScore ??
                  101
                )
              );
            }


            if (
              historySort ===
              "findings"
            ) {
              return (
                (
                  second.findings
                    ?.length ||
                  0
                ) -
                (
                  first.findings
                    ?.length ||
                  0
                )
              );
            }


            return (
              secondDate -
              firstDate
            );

          }
        );

      },

      [
        scans,
        historySearch,
        historyStatus,
        historySort,
      ]
    );


  // ====================================================
  // Selected Scan
  // ====================================================

  const pagesDiscovered =
    selected?.pages
      ?.length ||
    0;


  const formsFound =
    selected
      ?.discovery
      ?.forms
      ?.length ||
    0;


  const inputsFound =
    selected
      ?.discovery
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


  const apiRequestsFound =
    selected
      ?.discovery
      ?.apiRequests
      ?.length ||
    0;


  const selectedLiveProgress =
    liveProgress?.scanId ===
    selected?._id
      ? liveProgress
      : null;


  const progressPercent =
    selected
      ?.progress
      ?.percent ??
    selectedLiveProgress
      ?.percent ??
    0;


  const progressStage =
    selected
      ?.progress
      ?.stage ||
    selectedLiveProgress
      ?.stage ||
    "Preparing Scan";


  const progressMessage =
    selected
      ?.progress
      ?.message ||
    selectedLiveProgress
      ?.message ||
    "Waiting for scanner worker";


  // ====================================================
  // Findings
  // ====================================================

  const selectedFindings =
    useMemo(
      () =>
        selected?.findings ||
        [],

      [
        selected,
      ]
    );


  const owaspOptions =
    useMemo(
      () =>
        [
          ...new Set(
            selectedFindings
              .map(
                (
                  finding
                ) =>
                  finding.owasp
              )
              .filter(
                Boolean
              )
          ),
        ].sort(),

      [
        selectedFindings,
      ]
    );


  const owaspSummary =
    useMemo(
      () => {

        const summary =
          {};


        for (
          const finding
          of selectedFindings
        ) {

          const category =
            finding.owasp ||
            "Unmapped";


          summary[
            category
          ] =
            (
              summary[
                category
              ] ||
              0
            ) +
            1;
        }


        return Object.entries(
          summary
        ).sort(
          (
            a,
            b
          ) =>
            b[1] -
            a[1]
        );

      },

      [
        selectedFindings,
      ]
    );


  const filteredFindings =
    useMemo(
      () => {

        const search =
          findingSearch
            .trim()
            .toLowerCase();


        return selectedFindings.filter(
          (
            finding
          ) => {

            const matchesSeverity =
              severityFilter ===
                "All" ||
              finding.severity ===
                severityFilter;


            const matchesOwasp =
              owaspFilter ===
                "All" ||
              finding.owasp ===
                owaspFilter;


            const searchableText =
              [
                finding.title,
                finding.code,
                finding.severity,
                finding.owasp,
                finding.url,
                finding.evidence,
                finding.remediation,
              ]
                .filter(
                  Boolean
                )
                .join(" ")
                .toLowerCase();


            return (
              matchesSeverity &&
              matchesOwasp &&
              (
                !search ||
                searchableText.includes(
                  search
                )
              )
            );

          }
        );

      },

      [
        selectedFindings,
        findingSearch,
        severityFilter,
        owaspFilter,
      ]
    );


  // ====================================================
  // Login / Register UI
  // ====================================================

  if (
    !user
  ) {

    return (

      <main className="auth">

        <section className="auth-shell">

          <div className="auth-visual">

            <div className="auth-glow auth-glow-one" />

            <div className="auth-glow auth-glow-two" />


            <div className="auth-visual-content">

              <div className="auth-brand">

                <div className="auth-logo">

                  <Shield
                    size={27}
                  />

                </div>

                <span>
                  WebShield
                </span>

              </div>


              <div className="auth-hero">

                <span className="auth-eyebrow">

                  <Sparkles
                    size={15}
                  />

                  Intelligent Security Assessment

                </span>


                <h1>
                  Find vulnerabilities
                  <br />
                  before they become
                  <br />
                  <span>
                    real threats.
                  </span>
                </h1>


                <p>
                  Automated OWASP-focused security
                  assessment with dynamic crawling,
                  vulnerability detection, regression
                  tracking and professional reporting.
                </p>

              </div>


              <div className="auth-feature-list">

                <div className="auth-feature">

                  <div className="auth-feature-icon">

                    <Radar
                      size={20}
                    />

                  </div>

                  <div>

                    <strong>
                      Smart Discovery
                    </strong>

                    <span>
                      Dynamic crawling with Playwright
                    </span>

                  </div>

                </div>


                <div className="auth-feature">

                  <div className="auth-feature-icon">

                    <ShieldCheck
                      size={20}
                    />

                  </div>

                  <div>

                    <strong>
                      OWASP Security Analysis
                    </strong>

                    <span>
                      Findings mapped to security categories
                    </span>

                  </div>

                </div>


                <div className="auth-feature">

                  <div className="auth-feature-icon">

                    <LockKeyhole
                      size={20}
                    />

                  </div>

                  <div>

                    <strong>
                      Controlled Assessment
                    </strong>

                    <span>
                      Authorized lab-only scanning workflow
                    </span>

                  </div>

                </div>

              </div>


              <div className="auth-trust">

                <span className="auth-trust-dot" />

                Scanner Engine Ready

              </div>

            </div>

          </div>


          <div className="auth-form-side">

            <div className="auth-card">

              <div className="auth-mobile-brand">

                <Shield
                  size={25}
                />

                WebShield

              </div>


              <div className="auth-heading">

                <span className="auth-kicker">

                  {
                    mode ===
                      "login"
                      ? "WELCOME BACK"
                      : "GET STARTED"
                  }

                </span>


                <h2>

                  {
                    mode ===
                      "login"
                      ? "Access your workspace"
                      : "Create your account"
                  }

                </h2>


                <p>

                  {
                    mode ===
                      "login"
                      ? "Sign in to continue your security assessments."
                      : "Create a secure workspace for your WebShield assessments."
                  }

                </p>

              </div>


              <div className="auth-tabs">

                <button
                  type="button"

                  className={
                    mode ===
                      "login"
                      ? "auth-tab active"
                      : "auth-tab"
                  }

                  onClick={() =>
                    switchAuthMode(
                      "login"
                    )
                  }
                >
                  Sign In
                </button>


                <button
                  type="button"

                  className={
                    mode ===
                      "register"
                      ? "auth-tab active"
                      : "auth-tab"
                  }

                  onClick={() =>
                    switchAuthMode(
                      "register"
                    )
                  }
                >
                  Create Account
                </button>

              </div>


              <form
                className="auth-form"

                onSubmit={
                  submitAuth
                }
              >

                <label>

                  Email Address

                  <div className="auth-input-wrap">

                    <input
                      type="email"

                      placeholder="you@example.com"

                      value={
                        email
                      }

                      onChange={
                        (
                          event
                        ) =>
                          setEmail(
                            event.target.value
                          )
                      }

                      required
                    />

                  </div>

                </label>


                <label>

                  Password

                  <div className="auth-input-wrap">

                    <input
                      type={
                        showPassword
                          ? "text"
                          : "password"
                      }

                      placeholder={
                        mode ===
                          "register"
                          ? "Minimum 8 characters"
                          : "Enter your password"
                      }

                      minLength={8}

                      value={
                        password
                      }

                      onChange={
                        (
                          event
                        ) =>
                          setPassword(
                            event.target.value
                          )
                      }

                      required
                    />


                    <button
                      type="button"

                      className="password-toggle"

                      onClick={() =>
                        setShowPassword(
                          (
                            current
                          ) =>
                            !current
                        )
                      }
                    >

                      {
                        showPassword
                          ? (
                            <EyeOff
                              size={18}
                            />
                          )
                          : (
                            <Eye
                              size={18}
                            />
                          )
                      }

                    </button>

                  </div>

                </label>


                {
                  mode ===
                    "register" && (

                    <>

                      <label>

                        Confirm Password

                        <div className="auth-input-wrap">

                          <input
                            type={
                              showConfirmPassword
                                ? "text"
                                : "password"
                            }

                            placeholder="Enter password again"

                            value={
                              confirmPassword
                            }

                            onChange={
                              (
                                event
                              ) =>
                                setConfirmPassword(
                                  event.target.value
                                )
                            }

                            required
                          />


                          <button
                            type="button"

                            className="password-toggle"

                            onClick={() =>
                              setShowConfirmPassword(
                                (
                                  current
                                ) =>
                                  !current
                              )
                            }
                          >

                            {
                              showConfirmPassword
                                ? (
                                  <EyeOff
                                    size={18}
                                  />
                                )
                                : (
                                  <Eye
                                    size={18}
                                  />
                                )
                            }

                          </button>

                        </div>

                      </label>


                      <div className="password-requirements">

                        <div
                          className={
                            passwordChecks.length
                              ? "passed"
                              : ""
                          }
                        >

                          <CheckCircle2
                            size={14}
                          />

                          8+ characters

                        </div>


                        <div
                          className={
                            passwordChecks.letter
                              ? "passed"
                              : ""
                          }
                        >

                          <CheckCircle2
                            size={14}
                          />

                          Contains a letter

                        </div>


                        <div
                          className={
                            passwordChecks.number
                              ? "passed"
                              : ""
                          }
                        >

                          <CheckCircle2
                            size={14}
                          />

                          Contains a number

                        </div>

                      </div>

                    </>

                  )
                }


                {
                  error && (

                    <p className="error auth-error">
                      {error}
                    </p>

                  )
                }


                <button
                  className="auth-submit"

                  type="submit"

                  disabled={
                    busy
                  }
                >

                  {
                    busy
                      ? "Please wait..."
                      : mode ===
                          "login"
                        ? (
                          <>

                            <LockKeyhole
                              size={17}
                            />

                            Sign In Securely

                          </>
                        )
                        : (
                          <>

                            <ShieldCheck
                              size={17}
                            />

                            Create Secure Account

                          </>
                        )
                  }

                </button>

              </form>


              <div className="auth-divider">

                <span />

                <p>
                  OR CONTINUE WITH
                </p>

                <span />

              </div>


              <a
                className="google"

                href="/api/auth/google"
              >

                <span className="google-mark">
                  G
                </span>

                Continue with Google

              </a>


              <p className="auth-bottom-text">

                {
                  mode ===
                    "login"
                    ? "New to WebShield?"
                    : "Already have an account?"
                }


                <button
                  type="button"

                  onClick={() =>
                    switchAuthMode(
                      mode ===
                        "login"
                        ? "register"
                        : "login"
                    )
                  }
                >

                  {
                    mode ===
                      "login"
                      ? "Create account"
                      : "Sign in"
                  }

                </button>

              </p>


              <p className="auth-legal">
                By continuing, you confirm that WebShield
                will only be used against systems you are
                authorized to assess.
              </p>

            </div>

          </div>

        </section>

      </main>

    );
  }


  // ====================================================
  // Dashboard Analytics
  // ====================================================

  function renderDashboardAnalytics() {

    const circumference =
      2 *
      Math.PI *
      58;


    const gaugeScore =
      latestSecurityScore ??
      0;


    const dashOffset =
      circumference -
      (
        gaugeScore /
        100
      ) *
      circumference;


    return (

      <>

        <section className="analytics-grid">

          <article className="analytics-card">

            <div className="analytics-card-header">

              <div>

                <h3>
                  Security Posture
                </h3>

                <p>
                  Latest completed assessment
                </p>

              </div>


              <div className="analytics-icon">

                <Gauge
                  size={19}
                />

              </div>

            </div>


            {
              latestCompletedScan
                ? (

                  <div className="score-content">

                    <div className="score-gauge">

                      <svg
                        viewBox="0 0 140 140"
                      >

                        <circle
                          className="score-gauge-track"

                          cx="70"
                          cy="70"
                          r="58"
                        />


                        <circle
                          className="score-gauge-progress"

                          cx="70"
                          cy="70"
                          r="58"

                          stroke={
                            riskRating.color
                          }

                          strokeDasharray={
                            circumference
                          }

                          strokeDashoffset={
                            dashOffset
                          }
                        />

                      </svg>


                      <div className="score-gauge-value">

                        <strong>
                          {gaugeScore}
                        </strong>

                        <span>
                          out of 100
                        </span>

                      </div>

                    </div>


                    <div className="score-details">

                      <span
                        className={
                          `score-rating ${riskRating.className}`
                        }
                      >
                        {riskRating.label}
                      </span>


                      <small>
                        Latest scan security rating
                      </small>

                    </div>

                  </div>

                )
                : (

                  <div className="analytics-empty">

                    <Gauge
                      size={30}
                    />

                    <strong>
                      No security score yet
                    </strong>

                    <span>
                      Complete your first scan.
                    </span>

                  </div>

                )
            }

          </article>


          <article className="analytics-card">

            <div className="analytics-card-header">

              <div>

                <h3>
                  Finding Severity
                </h3>

                <p>
                  All recorded scan observations
                </p>

              </div>


              <div className="analytics-icon">

                <PieChart
                  size={19}
                />

              </div>

            </div>


            <div className="severity-content">

              <div
                className="severity-donut"

                style={{
                  background:
                    severityGradient,
                }}
              >

                <div className="severity-donut-center">

                  <strong>
                    {totalFindings}
                  </strong>

                  <span>
                    Findings
                  </span>

                </div>

              </div>


              <div className="severity-legend">

                {
                  [
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Info",
                  ].map(
                    (
                      severity
                    ) => (

                      <div
                        className="severity-legend-row"

                        key={
                          severity
                        }
                      >

                        <span
                          className={
                            `severity-dot ${severity.toLowerCase()}`
                          }
                        />

                        <span>
                          {severity}
                        </span>

                        <strong>
                          {
                            severityCounts[
                              severity
                            ]
                          }
                        </strong>

                      </div>

                    )
                  )
                }

              </div>

            </div>

          </article>


          <article className="analytics-card">

            <div className="analytics-card-header">

              <div>

                <h3>
                  Risk Overview
                </h3>

                <p>
                  Assessment health indicators
                </p>

              </div>


              <div className="analytics-icon">

                <AlertTriangle
                  size={19}
                />

              </div>

            </div>


            <div className="risk-posture-content">

              <div className="risk-posture-main">

                <div className="risk-posture-label">

                  <span>
                    Current Posture
                  </span>


                  <ShieldCheck
                    size={17}

                    color={
                      riskRating.color
                    }
                  />

                </div>


                <strong>
                  {riskRating.label}
                </strong>


                <p>
                  {
                    riskRating.description
                  }
                </p>

              </div>


              <div className="risk-mini-grid">

                <div className="risk-mini-card">

                  <span>
                    Average Score
                  </span>

                  <strong>

                    {
                      averageSecurityScore ===
                      null
                        ? "—"
                        : `${averageSecurityScore}/100`
                    }

                  </strong>

                </div>


                <div className="risk-mini-card">

                  <span>
                    High Impact
                  </span>

                  <strong>
                    {highSeverity}
                  </strong>

                </div>


                <div className="risk-mini-card">

                  <span>
                    Completed
                  </span>

                  <strong>
                    {completedScans}
                  </strong>

                </div>


                <div className="risk-mini-card">

                  <span>
                    Active Scans
                  </span>

                  <strong>
                    {runningScans}
                  </strong>

                </div>

              </div>

            </div>

          </article>

        </section>


        <section className="scan-trend-panel">

          <div className="scan-trend-header">

            <div>

              <h3>
                Security Score Trend
              </h3>

              <p>
                Most recent completed assessments
              </p>

            </div>


            <div className="analytics-icon">

              <TrendingUp
                size={19}
              />

            </div>

          </div>


          {
            recentTrendScans.length >
            0
              ? (

                <div className="scan-trend-chart">

                  {
                    recentTrendScans.map(
                      (
                        scan,
                        index
                      ) => {

                        const score =
                          Number.isFinite(
                            Number(
                              scan.securityScore
                            )
                          )
                            ? Number(
                                scan.securityScore
                              )
                            : 0;


                        return (

                          <div
                            className="scan-trend-column"

                            key={
                              scan._id
                            }
                          >

                            <span className="scan-trend-score">
                              {score}
                            </span>


                            <div className="scan-trend-bar-wrap">

                              <div
                                className="scan-trend-bar"

                                style={{
                                  height:
                                    `${Math.max(
                                      6,
                                      score
                                    )}%`,

                                  animationDelay:
                                    `${index * 80}ms`,
                                }}
                              />

                            </div>


                            <span className="scan-trend-label">

                              {
                                new Date(
                                  scan.finishedAt ||
                                  scan.createdAt
                                )
                                  .toLocaleDateString(
                                    "en-IN",
                                    {
                                      day:
                                        "2-digit",

                                      month:
                                        "short",
                                    }
                                  )
                              }

                            </span>

                          </div>

                        );

                      }
                    )
                  }

                </div>

              )
              : (

                <div className="analytics-empty">

                  <BarChart3
                    size={30}
                  />

                  <strong>
                    No trend data available
                  </strong>

                  <span>
                    Completed scans will appear here.
                  </span>

                </div>

              )
          }

        </section>

      </>

    );
  }


  // ====================================================
  // Dashboard
  // ====================================================

  function renderDashboardView() {

    return (

      <>

        <header>

          <div>

            <h1>
              Security Overview
            </h1>

            <p>
              Authorized web application security assessments
            </p>

          </div>


          <span className="pill">
            Lab-only Mode
          </span>

        </header>


        <section className="stats">

          <div>

            <span>
              Total Scans
            </span>

            <strong>
              {scans.length}
            </strong>

          </div>


          <div>

            <span>
              Completed
            </span>

            <strong>
              {completedScans}
            </strong>

          </div>


          <div>

            <span>
              Total Findings
            </span>

            <strong>
              {totalFindings}
            </strong>

          </div>


          <div>

            <span>
              High Impact
            </span>

            <strong>
              {highSeverity}
            </strong>

          </div>

        </section>


        {
          renderDashboardAnalytics()
        }


        <section className="panel">

          <h2>
            WebShield Scanner
          </h2>


          <p>
            Automated OWASP-focused vulnerability assessment
            with crawling, active checks, browser discovery,
            regression tracking and professional reporting.
          </p>


          <div className="discovery-grid">

            <div className="discovery-card">

              <span>
                Scanner Status
              </span>

              <strong>
                {
                  runningScans >
                  0
                    ? "Running"
                    : "Ready"
                }
              </strong>

            </div>


            <div className="discovery-card">

              <span>
                Scan Mode
              </span>

              <strong>
                Lab
              </strong>

            </div>


            <div className="discovery-card">

              <span>
                Authentication
              </span>

              <strong>
                Active
              </strong>

            </div>


            <div className="discovery-card">

              <span>
                Regression Tracking
              </span>

              <strong>
                Active
              </strong>

            </div>

          </div>


          <button
            type="button"

            onClick={() =>
              setActiveView(
                "new-scan"
              )
            }
          >
            Start New Scan
          </button>

        </section>


        {
          scans.length >
          0 && (

            <section className="panel">

              <h2>
                Recent Scans
              </h2>


              <div className="table">

                <div className="tr head">

                  <span>
                    Target
                  </span>

                  <span>
                    Status
                  </span>

                  <span>
                    Findings
                  </span>

                  <span>
                    Action
                  </span>

                </div>


                {
                  scans
                    .slice(
                      0,
                      5
                    )
                    .map(
                      (
                        scan
                      ) => (

                        <div
                          className="tr"

                          key={
                            scan._id
                          }
                        >

                          <span className="truncate">
                            {scan.url}
                          </span>


                          <span
                            className={
                              `status ${scan.status}`
                            }
                          >
                            {scan.status}
                          </span>


                          <span>
                            {
                              scan.findings
                                ?.length ||
                              0
                            }
                          </span>


                          <button
                            type="button"

                            className="link"

                            onClick={() => {

                              setActiveView(
                                "history"
                              );

                              openScan(
                                scan
                              );

                            }}
                          >
                            View
                          </button>

                        </div>

                      )
                    )
                }

              </div>

            </section>

          )
        }

      </>

    );
  }


  // ====================================================
  // New Scan
  // ====================================================

  function renderNewScanView() {

    return (

      <>

        <header>

          <div>

            <h1>
              New Security Scan
            </h1>

            <p>
              Start an authorized vulnerability assessment
            </p>

          </div>


          <span className="pill">
            Controlled Lab
          </span>

        </header>


        <section className="panel">

          <h2>
            Configure Scan
          </h2>


          <p>
            WebShield currently scans the bundled
            controlled laboratory target.
          </p>


          <form
            onSubmit={
              start
            }
          >

            <label>

              Target URL

              <input
                value={
                  url
                }

                onChange={
                  (
                    event
                  ) =>
                    setUrl(
                      event.target.value
                    )
                }

                required
              />

            </label>


            <label className="check">

              <input
                type="checkbox"

                checked={
                  authorized
                }

                onChange={
                  (
                    event
                  ) =>
                    setAuthorized(
                      event.target.checked
                    )
                }
              />

              I own or am authorized to test this target.

            </label>


            <button
              type="submit"

              disabled={
                !authorized ||
                busy
              }
            >

              {
                busy
                  ? "Starting Scan..."
                  : "Start Security Scan"
              }

            </button>

          </form>


          {
            error && (

              <p className="error">
                {error}
              </p>

            )
          }

        </section>


        <section className="panel">

          <h2>
            Scan Pipeline
          </h2>


          <div className="discovery-grid">

            {
              [
                [
                  "Step 1",
                  "Crawl",
                ],

                [
                  "Step 2",
                  "Analyze",
                ],

                [
                  "Step 3",
                  "Detect",
                ],

                [
                  "Step 4",
                  "Compare",
                ],
              ].map(
                (
                  [
                    step,
                    name,
                  ]
                ) => (

                  <div
                    className="discovery-card"

                    key={
                      step
                    }
                  >

                    <span>
                      {step}
                    </span>

                    <strong>
                      {name}
                    </strong>

                  </div>

                )
              )
            }

          </div>

        </section>

      </>

    );
  }


  // ====================================================
  // Comparison
  // ====================================================

  function renderComparisonList(
    title,
    findings
  ) {

    if (
      !findings ||
      findings.length ===
      0
    ) {
      return null;
    }


    return (

      <div className="comparison-list">

        <h4>
          {title}
        </h4>


        {
          findings.map(
            (
              finding,
              index
            ) => (

              <div
                className="comparison-item"

                key={
                  finding.fingerprint ||
                  index
                }
              >

                <strong>
                  {finding.title}
                </strong>


                <span
                  className={
                    `severity ${
                      finding.severity
                        ?.toLowerCase() ||
                      ""
                    }`
                  }
                >
                  {
                    finding.severity ||
                    "N/A"
                  }
                </span>


                <p>
                  {
                    finding.owasp ||
                    "OWASP mapping unavailable"
                  }
                </p>


                <small>
                  {finding.url}
                </small>

              </div>

            )
          )
        }

      </div>

    );
  }


  // ====================================================
  // Scan Details
  // ====================================================

  function renderScanDetails() {

    if (
      !selected
    ) {
      return null;
    }


    const comparison =
      selected.comparison;


    return (

      <section className="panel">

        <div className="heading">

          <h2>

            Scan Details{" "}

            <span
              className={
                `status ${selected.status}`
              }
            >
              {selected.status}
            </span>

          </h2>


          {
            selected.status ===
            "completed" && (

              <a
                className="download"

                href={
                  `/api/scans/${selected._id}/report`
                }
              >

                <Download
                  size={16}
                />

                PDF Report

              </a>

            )
          }

        </div>


        <p>

          <strong>
            Target:
          </strong>{" "}

          {selected.url}

        </p>


        <div className="scan-progress">

          <div className="progress-heading">

            <strong>
              {progressStage}
            </strong>

            <span>
              {progressPercent}%
            </span>

          </div>


          <div className="progress-track">

            <div
              className="progress-bar"

              style={{
                width:
                  `${progressPercent}%`,
              }}
            />

          </div>


          <p>
            {progressMessage}
          </p>

        </div>


        <div className="discovery-grid">

          <div className="discovery-card">

            <span>
              Pages Discovered
            </span>

            <strong>
              {pagesDiscovered}
            </strong>

          </div>


          <div className="discovery-card">

            <span>
              Forms Found
            </span>

            <strong>
              {formsFound}
            </strong>

          </div>


          <div className="discovery-card">

            <span>
              Inputs Found
            </span>

            <strong>
              {inputsFound}
            </strong>

          </div>


          <div className="discovery-card">

            <span>
              API Requests
            </span>

            <strong>
              {apiRequestsFound}
            </strong>

          </div>

        </div>


        <div className="security-score">

          <span>
            Security Score
          </span>

          <strong>
            {
              selected.securityScore ??
              100
            }
            /100
          </strong>

        </div>


        {
          selected.status ===
            "completed" &&
          comparison && (

            <div className="comparison-section">

              <h3>
                Vulnerability Comparison
              </h3>


              <p>

                {
                  comparison.hasPreviousScan
                    ? "Compared with the previous completed scan of the same target."
                    : "This scan is the baseline for future vulnerability comparisons."
                }

              </p>


              <div className="comparison-grid">

                <div className="comparison-stat">

                  <span>
                    New
                  </span>

                  <strong>
                    {
                      comparison.newCount ||
                      0
                    }
                  </strong>

                </div>


                <div className="comparison-stat">

                  <span>
                    Resolved
                  </span>

                  <strong>
                    {
                      comparison.resolvedCount ||
                      0
                    }
                  </strong>

                </div>


                <div className="comparison-stat">

                  <span>
                    Unchanged
                  </span>

                  <strong>
                    {
                      comparison.unchangedCount ||
                      0
                    }
                  </strong>

                </div>


                <div className="comparison-stat">

                  <span>
                    Status
                  </span>

                  <strong>
                    {
                      comparison.hasPreviousScan
                        ? "Compared"
                        : "Baseline"
                    }
                  </strong>

                </div>

              </div>


              {
                renderComparisonList(
                  "New Vulnerabilities",
                  comparison.newFindings
                )
              }


              {
                renderComparisonList(
                  "Resolved Vulnerabilities",
                  comparison.resolvedFindings
                )
              }


              {
                renderComparisonList(
                  "Unchanged Vulnerabilities",
                  comparison.unchangedFindings
                )
              }

            </div>

          )
        }


        {
          formsFound >
          0 && (

            <div className="discovery-section">

              <h3>
                Discovered Forms
              </h3>


              {
                selected
                  .discovery
                  .forms
                  .map(
                    (
                      form,
                      index
                    ) => (

                      <div
                        className="discovered-item"

                        key={
                          index
                        }
                      >

                        <strong>
                          {
                            form.method
                          }{" "}
                          {
                            form.action
                          }
                        </strong>


                        <p>
                          Page:{" "}
                          {form.page}
                        </p>


                        <p>

                          Inputs:{" "}

                          {
                            form.inputs
                              ?.map(
                                (
                                  input
                                ) =>
                                  input.name ||
                                  input.type
                              )
                              .join(
                                ", "
                              ) ||
                            "None"
                          }

                        </p>

                      </div>

                    )
                  )
              }

            </div>

          )
        }


        {
          apiRequestsFound >
          0 && (

            <div className="discovery-section">

              <h3>
                API Requests
              </h3>


              {
                selected
                  .discovery
                  .apiRequests
                  .map(
                    (
                      request,
                      index
                    ) => (

                      <div
                        className="discovered-item"

                        key={
                          index
                        }
                      >

                        <strong>
                          {
                            request.method
                          }{" "}
                          {
                            request.url
                          }
                        </strong>


                        <p>
                          Resource Type:{" "}
                          {
                            request.resourceType
                          }
                        </p>

                      </div>

                    )
                  )
              }

            </div>

          )
        }


        {
          selectedFindings.length >
          0 && (

            <div className="owasp-section">

              <h3>
                OWASP Findings Summary
              </h3>


              <div className="owasp-grid">

                {
                  owaspSummary.map(
                    (
                      [
                        category,
                        count,
                      ]
                    ) => (

                      <div
                        className="owasp-card"

                        key={
                          category
                        }
                      >

                        <span>
                          {category}
                        </span>

                        <strong>
                          {count}
                        </strong>

                      </div>

                    )
                  )
                }

              </div>

            </div>

          )
        }


        <div className="findings-section">

          <div className="findings-title-row">

            <div>

              <h3>
                Security Findings
              </h3>


              <p>
                Showing{" "}
                <strong>
                  {
                    filteredFindings.length
                  }
                </strong>{" "}
                of{" "}
                <strong>
                  {
                    selectedFindings.length
                  }
                </strong>{" "}
                findings
              </p>

            </div>


            <Filter
              size={22}
            />

          </div>


          <div className="finding-filters">

            <div className="search-box">

              <Search
                size={18}
              />


              <input
                type="text"

                placeholder="Search finding, URL, evidence..."

                value={
                  findingSearch
                }

                onChange={
                  (
                    event
                  ) =>
                    setFindingSearch(
                      event.target.value
                    )
                }
              />

            </div>


            <select
              value={
                severityFilter
              }

              onChange={
                (
                  event
                ) =>
                  setSeverityFilter(
                    event.target.value
                  )
              }
            >

              <option value="All">
                All Severities
              </option>

              <option value="Critical">
                Critical
              </option>

              <option value="High">
                High
              </option>

              <option value="Medium">
                Medium
              </option>

              <option value="Low">
                Low
              </option>

              <option value="Info">
                Info
              </option>

            </select>


            <select
              value={
                owaspFilter
              }

              onChange={
                (
                  event
                ) =>
                  setOwaspFilter(
                    event.target.value
                  )
              }
            >

              <option value="All">
                All OWASP Categories
              </option>


              {
                owaspOptions.map(
                  (
                    category
                  ) => (

                    <option
                      key={
                        category
                      }

                      value={
                        category
                      }
                    >
                      {category}
                    </option>

                  )
                )
              }

            </select>


            <button
              type="button"

              className="secondary"

              onClick={() => {

                setFindingSearch(
                  ""
                );

                setSeverityFilter(
                  "All"
                );

                setOwaspFilter(
                  "All"
                );

              }}
            >
              Clear Filters
            </button>

          </div>


          {
            filteredFindings.length ===
            0
              ? (

                <div className="empty-state">

                  <h4>
                    No findings match the current filters.
                  </h4>

                  <p>
                    Clear the filters to view all scan findings.
                  </p>

                </div>

              )
              : (

                filteredFindings.map(
                  (
                    finding,
                    index
                  ) => (

                    <article
                      className="finding"

                      key={
                        finding.fingerprint ||
                        index
                      }
                    >

                      <div className="finding-heading">

                        <div>

                          <b>
                            {
                              finding.title
                            }
                          </b>


                          {
                            finding.code && (

                              <small className="finding-code">
                                {
                                  finding.code
                                }
                              </small>

                            )
                          }

                        </div>


                        <span
                          className={
                            `severity ${
                              finding.severity
                                ?.toLowerCase()
                                .replace(
                                  " ",
                                  "-"
                                ) ||
                              ""
                            }`
                          }
                        >
                          {
                            finding.severity
                          }
                        </span>

                      </div>


                      <p className="finding-meta">

                        {
                          finding.owasp ||
                          "OWASP mapping unavailable"
                        }

                        {" · "}

                        Confidence:{" "}

                        {
                          finding.confidence ||
                          "N/A"
                        }

                      </p>


                      <div className="finding-url">
                        {finding.url}
                      </div>


                      <p>

                        <b>
                          Evidence:
                        </b>{" "}

                        {
                          finding.evidence ||
                          "N/A"
                        }

                      </p>


                      <p>

                        <b>
                          Remediation:
                        </b>{" "}

                        {
                          finding.remediation ||
                          "N/A"
                        }

                      </p>

                    </article>

                  )
                )

              )
          }

        </div>


        {
          selected.error && (

            <p className="error">
              {selected.error}
            </p>

          )
        }

      </section>

    );
  }


  // ====================================================
  // Professional Scan History
  // ====================================================

  function renderHistoryView() {

    return (

      <>

        <header>

          <div>

            <h1>
              Scan History
            </h1>

            <p>
              Review assessments, risk scores and vulnerability results
            </p>

          </div>


          <span className="pill">
            {scans.length} Scans
          </span>

        </header>


        <section className="panel">

          <div className="heading">

            <div>

              <h2>
                Security Assessments
              </h2>

              <p>
                Search, filter and compare previous WebShield scans.
              </p>

            </div>

          </div>


          <div className="history-toolbar">

            <div className="history-search">

              <Search
                size={17}
              />

              <input
                type="text"

                placeholder="Search target URL..."

                value={
                  historySearch
                }

                onChange={
                  (
                    event
                  ) =>
                    setHistorySearch(
                      event.target.value
                    )
                }
              />

            </div>


            <div className="history-select-wrap">

              <SlidersHorizontal
                size={16}
              />

              <select
                value={
                  historyStatus
                }

                onChange={
                  (
                    event
                  ) =>
                    setHistoryStatus(
                      event.target.value
                    )
                }
              >

                <option value="All">
                  All Statuses
                </option>

                <option value="completed">
                  Completed
                </option>

                <option value="running">
                  Running
                </option>

                <option value="queued">
                  Queued
                </option>

                <option value="failed">
                  Failed
                </option>

              </select>

            </div>


            <div className="history-select-wrap">

              <ArrowUpDown
                size={16}
              />

              <select
                value={
                  historySort
                }

                onChange={
                  (
                    event
                  ) =>
                    setHistorySort(
                      event.target.value
                    )
                }
              >

                <option value="newest">
                  Newest First
                </option>

                <option value="oldest">
                  Oldest First
                </option>

                <option value="score-high">
                  Highest Score
                </option>

                <option value="score-low">
                  Lowest Score
                </option>

                <option value="findings">
                  Most Findings
                </option>

              </select>

            </div>


            <button
              type="button"

              className="secondary"

              onClick={() => {

                setHistorySearch(
                  ""
                );

                setHistoryStatus(
                  "All"
                );

                setHistorySort(
                  "newest"
                );

              }}
            >

              <RotateCcw
                size={15}
              />

              Reset

            </button>

          </div>


          <div className="history-summary">

            <p>

              Showing{" "}

              <strong>
                {
                  filteredHistoryScans.length
                }
              </strong>{" "}

              of{" "}

              <strong>
                {scans.length}
              </strong>{" "}

              assessments

            </p>

          </div>


          {
            filteredHistoryScans.length ===
            0
              ? (

                <div className="history-empty">

                  <History
                    size={34}
                  />

                  <strong>
                    No assessments found
                  </strong>

                  <p>
                    Try changing the search or status filters.
                  </p>

                </div>

              )
              : (

                <div className="history-table">

                  <div className="history-row history-head">

                    <span>
                      Target
                    </span>

                    <span>
                      Assessment Date
                    </span>

                    <span>
                      Status
                    </span>

                    <span>
                      Score
                    </span>

                    <span>
                      Findings
                    </span>

                    <span>
                      Action
                    </span>

                  </div>


                  {
                    filteredHistoryScans.map(
                      (
                        scan
                      ) => {

                        const counts =
                          getScanSeverityCounts(
                            scan
                          );


                        const score =
                          scan.status ===
                            "completed" &&
                          Number.isFinite(
                            Number(
                              scan.securityScore
                            )
                          )
                            ? Number(
                                scan.securityScore
                              )
                            : null;


                        const scoreRating =
                          score ===
                            null
                            ? null
                            : getRiskRating(
                                score
                              );


                        return (

                          <div
                            className="history-row"

                            key={
                              scan._id
                            }
                          >

                            <div className="history-target">

                              <strong>
                                {scan.url}
                              </strong>

                              <span>
                                ID:{" "}
                                {
                                  String(
                                    scan._id
                                  ).slice(
                                    -10
                                  )
                                }
                              </span>

                            </div>


                            <div className="history-date">

                              <CalendarDays
                                size={14}
                              />

                              <span>

                                {
                                  formatScanDate(
                                    scan.finishedAt ||
                                    scan.startedAt ||
                                    scan.createdAt
                                  )
                                }

                              </span>

                            </div>


                            <span
                              className={
                                `status ${scan.status}`
                              }
                            >
                              {scan.status}
                            </span>


                            {
                              score ===
                                null
                                ? (

                                  <span className="history-score pending">
                                    —
                                  </span>

                                )
                                : (

                                  <span
                                    className={
                                      `history-score ${scoreRating.className}`
                                    }
                                  >
                                    {score}/100
                                  </span>

                                )
                            }


                            <div className="history-findings">

                              {
                                counts.Critical +
                                counts.High >
                                0 && (

                                  <span className="history-finding-pill high">

                                    H{" "}

                                    {
                                      counts.Critical +
                                      counts.High
                                    }

                                  </span>

                                )
                              }


                              {
                                counts.Medium >
                                0 && (

                                  <span className="history-finding-pill medium">

                                    M{" "}

                                    {
                                      counts.Medium
                                    }

                                  </span>

                                )
                              }


                              {
                                counts.Low >
                                0 && (

                                  <span className="history-finding-pill low">

                                    L{" "}

                                    {
                                      counts.Low
                                    }

                                  </span>

                                )
                              }


                              {
                                (
                                  scan.findings
                                    ?.length ||
                                  0
                                ) ===
                                  0 && (

                                  <span className="history-finding-pill none">
                                    No findings
                                  </span>

                                )
                              }

                            </div>


                            <button
                              type="button"

                              className="history-view-btn"

                              onClick={() =>
                                openScan(
                                  scan
                                )
                              }
                            >

                              View

                              <ExternalLink
                                size={13}
                              />

                            </button>

                          </div>

                        );

                      }
                    )
                  }

                </div>

              )
          }

        </section>


        {
          selected && (

            <div
              ref={
                scanDetailsRef
              }

              style={{
                scrollMarginTop:
                  "24px",
              }}
            >

              <button
                type="button"

                className="back-button"

                onClick={
                  closeScan
                }
              >

                <ArrowLeft
                  size={16}
                />

                Close Scan Details

              </button>


              {
                renderScanDetails()
              }

            </div>

          )
        }

      </>

    );
  }


  // ====================================================
  // Main App
  // ====================================================

  return (

    <div className="shell">

      <aside>

        <div className="brand">

          <Shield />

          WebShield

        </div>


        <button
          type="button"

          className={
            activeView ===
            "dashboard"
              ? "nav active"
              : "nav"
          }

          onClick={() =>
            setActiveView(
              "dashboard"
            )
          }
        >

          <Activity
            size={18}
          />

          Dashboard

        </button>


        <button
          type="button"

          className={
            activeView ===
            "new-scan"
              ? "nav active"
              : "nav"
          }

          onClick={() => {

            setActiveView(
              "new-scan"
            );

            setError(
              ""
            );

          }}
        >

          <ScanSearch
            size={18}
          />

          New Scan

        </button>


        <button
          type="button"

          className={
            activeView ===
            "history"
              ? "nav active"
              : "nav"
          }

          onClick={() =>
            setActiveView(
              "history"
            )
          }
        >

          <History
            size={18}
          />

          Scan History

        </button>


        <div className="bottom">

          <span>
            {user.email}
          </span>


          <button
            type="button"

            className="secondary"

            onClick={
              logout
            }
          >

            <LogOut
              size={16}
            />

            Sign Out

          </button>

        </div>

      </aside>


      <main className="content">

        {
          activeView ===
            "dashboard" &&
          renderDashboardView()
        }


        {
          activeView ===
            "new-scan" &&
          renderNewScanView()
        }


        {
          activeView ===
            "history" &&
          renderHistoryView()
        }

      </main>

    </div>

  );
}


// ======================================================
// Render
// ======================================================

createRoot(
  document.getElementById(
    "root"
  )
).render(
  <App />
);