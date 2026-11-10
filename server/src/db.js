import mongoose from "mongoose";


// ======================================================
// MongoDB Connection
// ======================================================

export async function connectDb() {
  const mongoUrl =
    process.env.MONGO_URL ||
    "mongodb://localhost:27017/webshield";

  await mongoose.connect(mongoUrl);

  return mongoose.connection;
}


// ======================================================
// Common Options
// ======================================================

const schemaOptions = {
  timestamps: true,
};


// ======================================================
// User Schema
// ======================================================

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      maxlength: 100,
      default: "",
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 200,
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
      enum: [
        "analyst",
        "admin",
      ],
      default: "analyst",
    },
  },
  schemaOptions
);

UserSchema.index({
  email: 1,
});

UserSchema.index({
  googleId: 1,
});

export const User =
  mongoose.model(
    "User",
    UserSchema
  );


// ======================================================
// Discovered Input
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


// ======================================================
// Discovered Form
// ======================================================

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
        type: [InputSchema],
        default: [],
      },
    },
    {
      _id: false,
    }
  );


// ======================================================
// Discovered API Request
// ======================================================

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
        default: "",
      },

      title: {
        type: String,
        default: "Security Finding",
      },

      severity: {
        type: String,
        default: "Informational",
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
        default: "",
      },

      status: {
        type: String,
        enum: [
          "Open",
          "Confirmed",
          "False Positive",
          "Accepted Risk",
          "Resolved",
        ],
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
// Scan Schema
// ======================================================

const ScanSchema =
  new mongoose.Schema(
    {
      owner: {
        type:
          mongoose.Schema.Types
            .ObjectId,

        ref: "User",

        required: true,
      },

      url: {
        type: String,
        required: true,
        trim: true,
      },

      status: {
        type: String,

        enum: [
          "queued",
          "running",
          "completed",
          "failed",
        ],

        default: "queued",
      },

      scanType: {
        type: String,

        enum: [
          "quick",
          "full",
          "custom",
        ],

        default: "full",
      },

      progress: {
        percent: {
          type: Number,
          default: 0,
          min: 0,
          max: 100,
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

      pages: {
        type: [String],
        default: [],
      },

      discovery: {
        forms: {
          type: [FormSchema],
          default: [],
        },

        apiRequests: {
          type: [
            ApiRequestSchema,
          ],
          default: [],
        },
      },

      findings: {
        type: [
          FindingSchema,
        ],
        default: [],
      },

      summary: {
        totalFindings: {
          type: Number,
          default: 0,
        },

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

        informational: {
          type: Number,
          default: 0,
        },

        pagesDiscovered: {
          type: Number,
          default: 0,
        },

        formsDiscovered: {
          type: Number,
          default: 0,
        },

        apiRequestsDiscovered: {
          type: Number,
          default: 0,
        },
      },

      securityScore: {
        type: Number,
        default: 100,
        min: 0,
        max: 100,
      },

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

    schemaOptions
  );


// ======================================================
// Indexes
// ======================================================

ScanSchema.index({
  owner: 1,
  createdAt: -1,
});

ScanSchema.index({
  owner: 1,
  status: 1,
});


// ======================================================
// Model
// ======================================================

export const Scan =
  mongoose.model(
    "Scan",
    ScanSchema
  );