import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import "dotenv/config";
import { z } from "zod";
import nodemailer from "nodemailer";

const app = express();

const envSchema = z.object({
    PORT: z.coerce.number().default(3002),
    FRONTEND_URL: z.string().min(1),
    SUPPORT_EMAIL: z.string().email(),
    SMTP_HOST: z.string().min(1),
    SMTP_PORT: z.coerce.number().default(587),
    SMTP_SECURE: z.string().optional(),
    SMTP_USER: z.string().min(1),
    SMTP_PASS: z.string().min(1),
    MAIL_FROM: z.string().min(1),
});

const env = envSchema.parse(process.env);

const allowedOrigins = env.FRONTEND_URL.split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

app.disable("x-powered-by");

app.use(
    helmet({
        contentSecurityPolicy: false,
    })
);

app.use(
    cors({
        origin(origin, callback) {
            if (!origin || allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            return callback(new Error("Not allowed by CORS"));
        },
        methods: ["GET", "POST"],
        allowedHeaders: ["Content-Type"],
        maxAge: 86400,
    })
);

app.use(express.json({ limit: "50kb", strict: true }));

app.use(
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 20,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            message: "Too many requests",
        },
    })
);

const supportLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Demasiadas solicitudes. Inténtalo más tarde.",
    },
});

const normalizeSingleLine = (value) => {
    return String(value)
        .replace(/[\r\n]+/g, " ")
        .replace(/[\u0000-\u001F\u007F-\u009F]/g, "")
        .replace(/[\u200B-\u200D\uFEFF]/g, "")
        .replace(/\s+/g, " ")
        .trim();
};

const normalizeMultiline = (value) => {
    return String(value)
        .replace(/\r\n?/g, "\n")
        .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, "")
        .replace(/[\u200B-\u200D\uFEFF]/g, "")
        .trim();
};

const hasHeaderInjection = (value) => {
    return /(?:\r|\n)\s*(?:to|from|cc|bcc|subject|reply-to|content-type|mime-version)\s*:/i.test(
        value
    );
};

const hasHighRiskInjection = (value) => {
    const patterns = [
        /<\s*\/?\s*(script|iframe|object|embed|link|meta|style|svg|form|input|textarea|button)\b/i,
        /\b(?:javascript|vbscript|data):/i,
        /\bon[a-z]+\s*=/i,
        /document\.cookie/i,
        /(?:\r|\n)\s*(?:to|from|cc|bcc|subject|reply-to|content-type|mime-version)\s*:/i,
    ];

    return patterns.some((pattern) => pattern.test(value));
};

const safeSingleLine = (min, max) => {
    return z
        .string()
        .transform(normalizeSingleLine)
        .pipe(
            z
                .string()
                .min(min)
                .max(max)
                .refine((value) => !hasHeaderInjection(value), {
                    message: "Invalid header characters",
                })
                .refine((value) => !hasHighRiskInjection(value), {
                    message: "Unsafe content detected",
                })
        );
};

const safeMessage = z
    .string()
    .transform(normalizeMultiline)
    .pipe(
        z
            .string()
            .min(10)
            .max(3000)
            .refine((value) => !hasHighRiskInjection(value), {
                message: "Unsafe content detected",
            })
    );

const optionalSafeSingleLine = (max) => {
    return z
        .string()
        .transform(normalizeSingleLine)
        .pipe(
            z
                .string()
                .max(max)
                .refine((value) => !hasHeaderInjection(value), {
                    message: "Invalid header characters",
                })
                .refine((value) => !hasHighRiskInjection(value), {
                    message: "Unsafe content detected",
                })
        )
        .optional();
};

const supportSchema = z
    .object({
        name: safeSingleLine(2, 80),
        email: z
            .string()
            .transform(normalizeSingleLine)
            .pipe(z.string().email().max(120))
            .transform((value) => value.toLowerCase()),

        subject: safeSingleLine(3, 120),
        message: safeMessage,
        tag: z.literal("splay-go"),

        source: optionalSafeSingleLine(120),

        pageUrl: z
            .string()
            .transform(normalizeSingleLine)
            .pipe(z.string().url().max(500))
            .optional(),

        userAgent: optionalSafeSingleLine(300),

        website: z
            .string()
            .transform(normalizeSingleLine)
            .pipe(z.string().max(120))
            .optional()
            .default(""),

        startedAt: z.number().finite().int().positive().optional(),
    })
    .strict();

const transporter = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_SECURE === "true",
    auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASS,
    },
});

const escapeHtml = (value) => {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
};

app.get("/", (req, res) => {
    res.json({
        ok: true,
        service: "SPlay GO Support API",
    });
});

app.post("/support", supportLimiter, async (req, res) => {
    const parsed = supportSchema.safeParse(req.body);

    if (!parsed.success) {
        return res.status(400).json({
            message: "Invalid support request",
            errors: parsed.error.flatten(),
        });
    }

    const now = Date.now();

    if (parsed.data.website) {
        return res.status(200).json({
            ok: true,
            message: "Support request sent",
        });
    }

    if (parsed.data.startedAt && now - parsed.data.startedAt < 3000) {
        return res.status(400).json({
            message: "Invalid support request",
            errors: {
                formErrors: ["El formulario fue enviado demasiado rápido."],
                fieldErrors: {},
            },
        });
    }

    const { name, email, subject, message, tag, source, pageUrl, userAgent } =
        parsed.data;

    const mailSubject = `[${tag}] ${subject}`;

    try {
        const info = await transporter.sendMail({
            from: env.MAIL_FROM,
            to: env.SUPPORT_EMAIL,
            replyTo: email,
            subject: mailSubject,
            text: [
                "Nueva solicitud de soporte de SPlay GO",
                "",
                `Nombre: ${name}`,
                `Correo: ${email}`,
                `Etiqueta: ${tag}`,
                `Origen: ${source || "N/A"}`,
                `Página: ${pageUrl || "N/A"}`,
                `Navegador: ${userAgent || "N/A"}`,
                "",
                "Mensaje:",
                message,
            ].join("\n"),
            html: `
                <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.6;">
                    <h2 style="margin: 0 0 12px;">Nueva solicitud de soporte de SPlay GO</h2>

                    <div style="padding: 12px 16px; background: #f3f4f6; border-radius: 12px; margin-bottom: 16px;">
                        <p><strong>Etiqueta:</strong> ${escapeHtml(tag)}</p>
                        <p><strong>Asunto:</strong> ${escapeHtml(subject)}</p>
                    </div>

                    <p><strong>Nombre:</strong> ${escapeHtml(name)}</p>
                    <p><strong>Correo:</strong> ${escapeHtml(email)}</p>

                    <hr />

                    <h3>Mensaje</h3>
                    <p>${escapeHtml(message).replaceAll("\n", "<br />")}</p>

                    <hr />

                    <p><strong>Origen:</strong> ${escapeHtml(source || "N/A")}</p>
                    <p><strong>Página:</strong> ${escapeHtml(pageUrl || "N/A")}</p>
                    <p><strong>Navegador:</strong> ${escapeHtml(userAgent || "N/A")}</p>
                </div>
            `,
        });

        console.log("Support mail sent:", {
            messageId: info.messageId,
            accepted: info.accepted,
            rejected: info.rejected,
            response: info.response,
        });

        return res.status(200).json({
            ok: true,
            message: "Support request sent",
        });
    } catch (error) {
        console.error("Support mail error:", error);

        return res.status(500).json({
            message: "Could not send support request",
        });
    }
});

app.use((err, req, res, next) => {
    if (err.message === "Not allowed by CORS") {
        return res.status(403).json({
            message: "Origin not allowed",
        });
    }

    return res.status(500).json({
        message: "Internal server error",
    });
});

app.listen(env.PORT, "0.0.0.0", () => {
    console.log(`SPlay GO Support API running on http://localhost:${env.PORT}`);
});