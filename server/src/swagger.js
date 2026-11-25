
import swaggerJsdoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.3",
    info: {
      title: "WebShield API",
      version: "1.0.0",
      description:
        "API documentation for WebShield vulnerability scanner. Scans are restricted to authorized lab targets.",
    },
    servers: [
      {
        url: "https://webshield-api-n7dx.onrender.com",
        description: "Production API",
      },
      {
        url: "http://localhost:5000",
        description: "Local API",
      },
    ],
    tags: [
      { name: "Health" },
      { name: "Authentication" },
      { name: "Scans" },
    ],
    components: {
      securitySchemes: {
        cookieAuth: {
          type: "apiKey",
          in: "cookie",
          name: "token",
        },
      },
      schemas: {
        Error: {
          type: "object",
          properties: {
            error: { type: "string" },
          },
        },
      },
    },
  },
  apis: [],
};

export const swaggerSpec = swaggerJsdoc(options);
