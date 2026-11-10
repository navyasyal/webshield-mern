import React, {
  useEffect,
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
} from "lucide-react";

import "./style.css";


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
      .catch(
        () => ({})
      );


  if (
    !response.ok
  ) {
    throw new Error(
      data.error ||
      "Request failed"
    );
  }


  return data;
}


// ======================================================
// App
// ======================================================

function App() {
  const [
    user,
    setUser,
  ] = useState(
    null
  );


  const [
    mode,
    setMode,
  ] = useState(
    "login"
  );


  const [
    email,
    setEmail,
  ] = useState(
    ""
  );


  const [
    password,
    setPassword,
  ] = useState(
    ""
  );


  const [
    activeView,
    setActiveView,
  ] = useState(
    "dashboard"
  );


  const [
    error,
    setError,
  ] = useState(
    ""
  );


  const [
    busy,
    setBusy,
  ] = useState(
    false
  );


  const [
    url,
    setUrl,
  ] = useState(
    "http://lab:4000/"
  );


  const [
    authorized,
    setAuthorized,
  ] = useState(
    false
  );


  const [
    scans,
    setScans,
  ] = useState(
    []
  );


  const [
    selected,
    setSelected,
  ] = useState(
    null
  );


  const [
    liveProgress,
    setLiveProgress,
  ] = useState(
    null
  );


  // ====================================================
  // Load User + Scans
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
  // Polling
  // ====================================================

  useEffect(
    () => {
      if (
        !user
      ) {
        return;
      }


      const timer =
        setInterval(
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
              // Ignore polling errors
            }
          },

          3000
        );


      return () => {
        clearInterval(
          timer
        );
      };
    },

    [
      user,
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

        (
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

    setError(
      ""
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


      setSelected(
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
      setBusy(
        false
      );
    }
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
  // Auth UI
  // ====================================================

  if (
    !user
  ) {
    return (
      <main className="auth">

        <div className="auth-card">

          <div className="brand">
            <Shield size={30} />

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
  // Dashboard Stats
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
      )
      .length;


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
  // Dashboard
  // ====================================================

  function DashboardView() {
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
                              setSelected(
                                scan
                              );

                              setActiveView(
                                "history"
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

  function NewScanView() {
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
            WebShield currently
            scans the bundled
            controlled laboratory
            target.
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
  // Comparison Finding List
  // ====================================================

  function ComparisonList({
    title,
    findings,
  }) {
    if (
      !findings ||
      findings.length ===
        0
    ) {
      return null;
    }


    return (
      <div className="discovery-section">

        <h3>
          {title}
        </h3>


        {
          findings.map(
            (
              finding,
              index
            ) => (

              <div
                className="discovered-item"

                key={
                  finding.fingerprint ||
                  index
                }
              >

                <strong>
                  {
                    finding.title
                  }
                </strong>


                <p>
                  Severity:{" "}
                  {
                    finding.severity ||
                    "N/A"
                  }
                </p>


                <p>
                  {
                    finding.owasp ||
                    "OWASP mapping unavailable"
                  }
                </p>


                <small>
                  {
                    finding.url
                  }
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

  function ScanDetails() {
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
              {
                selected.status
              }
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


        {/* Score */}

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


        {/* ==================================================
            Scan Comparison
            ================================================== */}

        {
          selected.status ===
            "completed" &&
          comparison && (

            <div className="discovery-section">

              <h3>
                Vulnerability Comparison
              </h3>


              {
                comparison.hasPreviousScan
                  ? (

                    <p>
                      Compared with the
                      previous completed
                      scan of the same
                      target.
                    </p>

                  )
                  : (

                    <p>
                      This is the first
                      completed scan for
                      this target. All
                      detected findings
                      are considered new.
                    </p>

                  )
              }


              <div className="discovery-grid">

                <div className="discovery-card">

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


                <div className="discovery-card">

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


                <div className="discovery-card">

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


                <div className="discovery-card">

                  <span>
                    Comparison
                  </span>

                  <strong>
                    {
                      comparison.hasPreviousScan
                        ? "Available"
                        : "Baseline"
                    }
                  </strong>

                </div>

              </div>


              <ComparisonList
                title="New Vulnerabilities"

                findings={
                  comparison.newFindings
                }
              />


              <ComparisonList
                title="Resolved Vulnerabilities"

                findings={
                  comparison.resolvedFindings
                }
              />


              <ComparisonList
                title="Unchanged Vulnerabilities"

                findings={
                  comparison.unchangedFindings
                }
              />

            </div>

          )
        }


        {/* Error */}

        {
          selected.error && (
            <p className="error">
              {
                selected.error
              }
            </p>
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
                          {
                            form.page
                          }
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


        {/* Findings */}

        <div className="findings-section">

          <h3>
            Security Findings
          </h3>


          {
            (
              selected.findings ||
              []
            ).length ===
            0
              ? (

                <p>
                  No security findings
                  currently available.
                </p>

              )
              : (

                selected.findings.map(
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

                        <b>
                          {
                            finding.title
                          }
                        </b>


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


                      <p>

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


                      <small>
                        {finding.url}
                      </small>


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

      </section>
    );
  }


  // ====================================================
  // History
  // ====================================================

  function HistoryView() {
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
                              {
                                scan.url
                              }
                            </span>


                            <span
                              className={
                                `status ${scan.status}`
                              }
                            >
                              {
                                scan.status
                              }
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
                                setSelected(
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

            <>
              <button
                type="button"

                className="link"

                onClick={() =>
                  setSelected(
                    null
                  )
                }

                style={{
                  marginBottom:
                    "12px",
                }}
              >

                <ArrowLeft
                  size={16}
                />{" "}

                Close Scan Details

              </button>


              <ScanDetails />

            </>

          )
        }

      </>
    );
  }


  // ====================================================
  // Main UI
  // ====================================================

  return (
    <div className="shell">

      <aside>

        <div className="brand">

          <Shield />

          WebShield

        </div>


        <div
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

          style={{
            cursor:
              "pointer",
          }}
        >

          <Activity
            size={18}
          />

          Dashboard

        </div>


        <div
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

          style={{
            cursor:
              "pointer",
          }}
        >

          <ScanSearch
            size={18}
          />

          New Scan

        </div>


        <div
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

          style={{
            cursor:
              "pointer",
          }}
        >

          <History
            size={18}
          />

          Scan History

        </div>


        <div className="bottom">

          <span>
            {user.email}
          </span>


          <button
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
            "dashboard" && (
            <DashboardView />
          )
        }


        {
          activeView ===
            "new-scan" && (
            <NewScanView />
          )
        }


        {
          activeView ===
            "history" && (
            <HistoryView />
          )
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