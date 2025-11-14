/**
 * This is not a production server yet!
 * This is only a minimal backend to get started.
 */

import express from 'express';
import cors from 'cors';
import proxy from 'express-http-proxy';
import morgan from 'morgan';
import rateLimit, {ipKeyGenerator} from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express'
import axios from 'axios';
import cookieParser from 'cookie-parser';

const app = express();

app.use(cors({
  origin: ["http://localhost:3000"],
  credentials: true,
  allowedHeaders: ["Authorization", "Content-Type"],
}));

app.use(morgan("dev"));
app.use(express.json({ limit: '100mb' } ));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(cookieParser());
app.set('trust proxy', 1);

// Apply rate limit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: (req: any) => (req.user ? 1000 : 100),
  message: { error: "Too many request. Please try again later" },
  standardHeaders: true,
  legacyHeaders: true,
  keyGenerator: (req, res) => {
    return ipKeyGenerator((req.ip || "0.0.0.0") as string);
  },
});

app.use(limiter);

app.get('/gateway-health', (req, res) => {
  res.send({ message: 'Welcome to api-gateway!' });
});

app.use('/', proxy('http://localhost:6001'));

const port = process.env.PORT || 8080;
const server = app.listen(port, () => {
  console.log(`Listening at http://localhost:${port}/api`);
});
server.on('error', console.error);
