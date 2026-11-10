import mongoose from "mongoose";


// ======================================================
// MongoDB Connection
// ======================================================

export async function connectDb() {
  const mongoUrl =
    process.env.MONGO_URL ||
    "mongodb://mongo:27017/webshield";

  await mongoose.connect(
    mongoUrl
  );

  console.log(
    "MongoDB connected"
  );
}


// ======================================================
// User Schema
// ======================================================

const UserSchema =
  new mongoose.Schema(
    {
      name: {
        type: String,
        trim: true,
        default: "",
      },

      email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
      },

      passwordHash: {
        type: String,
        default: null,
      },

      googleId: {
        type: String,
        default: null,
      },

      role: {
        type: String,
        default: "user",
      },
    },
    {
      timestamps: true,
    }
  );


// ======================================================
// Dynamic Discovery Schemas
// ======================================================

const InputSchema =
  new mongoose.Schema(
    {
      name: {
        type: String,
        default: "",
      },

      type: {
        type: String,
        default: "",
      },
    },
    {
      _id: false,
    }
  );


const FormSchema =
  new mongoose.Schema(
    {
      page: {
        type: String,
        default: "",
      },

      action: {
        type: String,
        default: "",
      },

      method: {
        type: String,
        default: "GET",
      },

      inputs: {
        type: [
          InputSchema,
        ],

        default: [],
      },
    },
    {
      _id: false,
    }
  );


const ApiRequestSchema =
  new mongoose.Schema(
    {
      url: {
        type: String,
        default: "",
      },

      method: {
        type: String,
        default: "GET",
      },

      resourceType: {
        type: String,
        default: "",
      },
    },
    {
      _id: false,
    }
  );


// ======================================================
// Finding Schema
// ======================================================

const FindingSchema =
  new mongoose.Schema(
    {
      code: {
        type: String,
        required: true,
      },

      title: {
        type: String,
        required: true,
      },

      severity: {
        type: String,

        enum: [
          "Critical",
          "High",
          "Medium",
          "Low",
          "Info",
        ],

        default: "Low",
      },

      confidence: {
        type: String,
        default: "Medium",
      },

      owasp: {
        type: String,
        default: "",
      },

      url: {
        type: String,
        default: "",
      },

      evidence: {
        type: String,
        default: "",
      },

      remediation: {
        type: String,
        default: "",
      },

      fingerprint: {
        type: String,
        required: true,
      },

      status: {
        type: String,
        default: "Open",
      },

      firstSeen: {
        type: Date,
        default: Date.now,
      },

      lastSeen: {
        type: Date,
        default: Date.now,
      },

      occurrenceCount: {
        type: Number,
        default: 1,
      },
    },
    {
      _id: false,
    }
  );


// ======================================================
// Comparison Snapshot
// ======================================================

const FindingSnapshotSchema =
  new mongoose.Schema(
    {
      fingerprint: {
        type: String,
        default: "",
      },

      code: {
        type: String,
        default: "",
      },

      title: {
        type: String,
        default: "",
      },

      severity: {
        type: String,
        default: "",
      },

      owasp: {
        type: String,
        default: "",
      },

      url: {
        type: String,
        default: "",
      },
    },
    {
      _id: false,
    }
  );


// ======================================================
// Scan Schema
// ======================================================

const ScanSchema =
  new mongoose.Schema(
    {
      owner: {
        type:
          mongoose.Schema.Types.ObjectId,

        ref:
          "User",

        required:
          true,

        index:
          true,
      },

      url: {
        type: String,
        required: true,
      },

      status: {
        type: String,

        enum: [
          "queued",
          "running",
          "completed",
          "failed",
        ],

        default:
          "queued",

        index:
          true,
      },

      scanType: {
        type: String,

        enum: [
          "quick",
          "full",
          "custom",
        ],

        default:
          "full",
      },


      // ================================================
      // Live Progress
      // ================================================

      progress: {
        percent: {
          type: Number,
          default: 0,
        },

        stage: {
          type: String,
          default: "Queued",
        },

        message: {
          type: String,
          default:
            "Waiting for scanner worker",
        },
      },


      // ================================================
      // Discovered Pages
      // ================================================

      pages: {
        type: [
          String,
        ],

        default:
          [],
      },


      // ================================================
      // Dynamic Discovery
      // ================================================

      discovery: {
        forms: {
          type: [
            FormSchema,
          ],

          default:
            [],
        },

        apiRequests: {
          type: [
            ApiRequestSchema,
          ],

          default:
            [],
        },
      },


      // ================================================
      // Findings
      // ================================================

      findings: {
        type: [
          FindingSchema,
        ],

        default:
          [],
      },


      // ================================================
      // Scan Summary
      // ================================================

      summary: {
        critical: {
          type: Number,
          default: 0,
        },

        high: {
          type: Number,
          default: 0,
        },

        medium: {
          type: Number,
          default: 0,
        },

        low: {
          type: Number,
          default: 0,
        },

        info: {
          type: Number,
          default: 0,
        },

        pages: {
          type: Number,
          default: 0,
        },

        forms: {
          type: Number,
          default: 0,
        },

        apiRequests: {
          type: Number,
          default: 0,
        },
      },


      // ================================================
      // Security Score
      // ================================================

      securityScore: {
        type: Number,
        default: 100,
      },


      // ================================================
      // Regression / Comparison Tracking
      // ================================================

      comparison: {
        hasPreviousScan: {
          type: Boolean,
          default: false,
        },

        previousScanId: {
          type:
            mongoose.Schema.Types.ObjectId,

          ref:
            "Scan",

          default:
            null,
        },

        previousFinishedAt: {
          type: Date,
          default: null,
        },

        newCount: {
          type: Number,
          default: 0,
        },

        resolvedCount: {
          type: Number,
          default: 0,
        },

        unchangedCount: {
          type: Number,
          default: 0,
        },

        newFindings: {
          type: [
            FindingSnapshotSchema,
          ],

          default: [],
        },

        resolvedFindings: {
          type: [
            FindingSnapshotSchema,
          ],

          default: [],
        },

        unchangedFindings: {
          type: [
            FindingSnapshotSchema,
          ],

          default: [],
        },
      },


      // ================================================
      // Error / Timing
      // ================================================

      error: {
        type: String,
        default: null,
      },

      startedAt: {
        type: Date,
        default: null,
      },

      finishedAt: {
        type: Date,
        default: null,
      },
    },
    {
      timestamps: true,
    }
  );


// ======================================================
// Useful Indexes
// ======================================================

ScanSchema.index({
  owner: 1,
  createdAt: -1,
});


ScanSchema.index({
  owner: 1,
  status: 1,
});


ScanSchema.index({
  owner: 1,
  url: 1,
  finishedAt: -1,
});


// ======================================================
// Models
// ======================================================

export const User =
  mongoose.models.User ||
  mongoose.model(
    "User",
    UserSchema
  );


export const Scan =
  mongoose.models.Scan ||
  mongoose.model(
    "Scan",
    ScanSchema
  );