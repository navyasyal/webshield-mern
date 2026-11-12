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
} from "lucide-react";

import "./style.css";


// ======================================================
// API Helper
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
      .catch(
        () => ({})
      );

  if (!response.ok) {
    throw new Error(
      data.error ||
      "Request failed"
    );
  }

  return data;
}


// ======================================================
// Application
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
  ] = useState("login");

  const [
    email,
    setEmail,
  ] = useState("");

  const [
    password,
    setPassword,
  ] = useState("");


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
  // Smooth Scan Details Scroll
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
  ] = useState("All");

  const [
    owaspFilter,
    setOwaspFilter,
  ] = useState("All");


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
  // Poll Only While Scan Is Running
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

              if (current) {

                setSelected(
                  current
                );

              }
            }

          } catch {

            // Ignore temporary polling errors

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
  // Smooth Scroll To Details
  //
  // IMPORTANT:
  // Runs only when View is explicitly clicked.
  // It does NOT run on polling/filter changes.
  // ====================================================

  useEffect(
    () => {

      if (
        scrollRequest === 0 ||
        activeView !==
          "history" ||
        !selected?._id
      ) {
        return;
      }


      const timer =
        window.setTimeout(
          () => {

            if (
              scanDetailsRef.current
            ) {

              scanDetailsRef
                .current
                .scrollIntoView({
                  behavior:
                    "smooth",

                  block:
                    "start",
                });

            }

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

      if (!user) {
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
        "connect",

        () => {

          console.log(
            "Socket connected:",
            socket.id
          );

        }
      );


      socket.on(
        "scan:progress",

        async (
          event
        ) => {

          setLiveProgress(
            event
          );


          // --------------------------------------------
          // Update history row
          // --------------------------------------------

          setScans(
            (
              currentScans
            ) =>
              currentScans.map(
                (
                  scan
                ) => {

                  if (
                    scan._id !==
                    event.scanId
                  ) {
                    return scan;
                  }


                  return {
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
                  };

                }
              )
          );


          // --------------------------------------------
          // Update selected scan
          // --------------------------------------------

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


          // --------------------------------------------
          // Fetch final complete result once
          // --------------------------------------------

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
                ) => {

                  if (
                    current?._id ===
                    event.scanId
                  ) {
                    return finalScan;
                  }


                  return current;

                }
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


      socket.on(
        "connect_error",

        (
          socketError
        ) => {

          console.error(
            "Socket error:",
            socketError.message
          );

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

  async function submitAuth(
    event
  ) {

    event.preventDefault();

    setError("");


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


      setPassword("");

      await load();

    } catch (
      authError
    ) {

      setError(
        authError.message
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

    setBusy(true);

    setError("");

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


      const updated =
        await api(
          "/scans"
        );


      setScans(
        updated
      );

    } catch (
      scanError
    ) {

      setError(
        scanError.message
      );

    } finally {

      setBusy(false);

    }
  }


  // ====================================================
  // Open Scan
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


    // Trigger smooth scroll only
    // because the user explicitly opened a scan.

    setScrollRequest(
      (
        current
      ) =>
        current +
        1
    );

  }


  // ====================================================
  // Close Scan
  // ====================================================

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


    setUser(null);

    setSelected(null);

    setLiveProgress(
      null
    );

    setActiveView(
      "dashboard"
    );
  }


  // ====================================================
  // Dashboard Statistics
  // ====================================================

  const totalFindings =
    scans.reduce(
      (
        total,
        scan
      ) =>
        total +
        (
          scan.findings
            ?.length ||
          0
        ),

      0
    );


  const completedScans =
    scans.filter(
      (
        scan
      ) =>
        scan.status ===
        "completed"
    ).length;


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


  const highSeverity =
    scans
      .flatMap(
        (
          scan
        ) =>
          scan.findings ||
          []
      )
      .filter(
        (
          finding
        ) =>
          finding.severity ===
          "High"
      ).length;


  // ====================================================
  // Selected Scan Statistics
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


  // ====================================================
  // OWASP Options
  // ====================================================

  const owaspOptions =
    useMemo(
      () => {

        return [
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
        ].sort();

      },

      [
        selectedFindings,
      ]
    );


  // ====================================================
  // OWASP Summary
  // ====================================================

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
            ) + 1;

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


  // ====================================================
  // Filtered Findings
  // ====================================================

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


            const matchesSearch =
              !search ||
              searchableText.includes(
                search
              );


            return (
              matchesSeverity &&
              matchesOwasp &&
              matchesSearch
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
  // Login
  // ====================================================

  if (!user) {

    return (

      <main className="auth">

        <div className="auth-card">

          <div className="brand">

            <Shield
              size={30}
            />

            WebShield

          </div>


          <h1>
            Security Scanner
          </h1>


          <p>
            Sign in to your
            authorized security
            assessment workspace.
          </p>


          <form
            onSubmit={
              submitAuth
            }
          >

            <label>

              Email

              <input
                type="email"

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

            </label>


            <label>

              Password

              <input
                type="password"

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

            </label>


            {
              error && (

                <p className="error">
                  {error}
                </p>

              )
            }


            <button
              type="submit"
            >

              {
                mode ===
                "login"
                  ? "Sign In"
                  : "Create Account"
              }

            </button>

          </form>


          <a
            className="google"

            href="/api/auth/google"
          >
            Continue with Google
          </a>


          <button
            type="button"

            className="link"

            onClick={() =>
              setMode(
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
                ? "Create an account"
                : "Back to sign in"
            }

          </button>

        </div>

      </main>

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
              Authorized web
              application security
              assessments
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
              High Severity
            </span>

            <strong>
              {highSeverity}
            </strong>

          </div>

        </section>


        <section className="panel">

          <h2>
            WebShield Scanner
          </h2>


          <p>
            Automated OWASP-focused
            vulnerability assessment
            with crawling, active
            checks, browser discovery,
            regression tracking and
            reporting.
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
              Start an authorized
              vulnerability assessment
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
            WebShield currently scans
            the bundled controlled
            laboratory target.
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

              I own or am authorized
              to test this target.

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

            <div className="discovery-card">

              <span>
                Step 1
              </span>

              <strong>
                Crawl
              </strong>

            </div>


            <div className="discovery-card">

              <span>
                Step 2
              </span>

              <strong>
                Analyze
              </strong>

            </div>


            <div className="discovery-card">

              <span>
                Step 3
              </span>

              <strong>
                Detect
              </strong>

            </div>


            <div className="discovery-card">

              <span>
                Step 4
              </span>

              <strong>
                Compare
              </strong>

            </div>

          </div>

        </section>

      </>

    );
  }


  // ====================================================
  // Comparison List
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

    if (!selected) {
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


        {/* Progress */}

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


        {/* Discovery */}

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


        {/* Security Score */}

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


        {/* Comparison */}

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


        {/* Forms */}

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


        {/* API Requests */}

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


        {/* OWASP */}

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


        {/* Findings */}

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

                setFindingSearch("");

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
                    No findings match
                    the current filters.
                  </h4>


                  <p>
                    Clear the filters
                    to view all scan
                    findings.
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

                        {
                          finding.url
                        }

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
  // History
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
              Review previous
              assessments and
              vulnerability changes
            </p>

          </div>


          <span className="pill">
            {scans.length} Scans
          </span>

        </header>


        <section className="panel">

          <h2>
            Security Assessments
          </h2>


          {
            scans.length ===
            0
              ? (

                <p>
                  No scans available.
                </p>

              )
              : (

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
                    scans.map(
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

                            onClick={() =>
                              openScan(
                                scan
                              )
                            }
                          >
                            View
                          </button>

                        </div>

                      )
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
  // UI
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

            setError("");

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