import express, { Express } from 'express';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import swaggerSpec from "./swagger";
import helmet from 'helmet';
import morgan from 'morgan';
import authRoutes from './routes/authRoutes';

const app: Express = express();

app.use(cors());
app.use(express.json());
app.use(morgan('dev')); 
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use('/api/auth', authRoutes);

const PORT: number = parseInt(process.env.PORT || '5000', 10);
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));