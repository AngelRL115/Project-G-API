import express from 'express'
import baseRouter from './routes/baseRouter'
import bodyParser from 'body-parser'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
const swaggerUi = require('swagger-ui-express')
const swaggerJsdoc = require('swagger-jsdoc')
import * as dotenv from 'dotenv'

dotenv.config()

const app = express()
const port = process.env.PORT || 3000
const logger = morgan('combined')

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(helmet())
app.use(cors())
app.use(logger)
app.use(bodyParser.json({ limit: '100mb' }))
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }))
app.disable('x-powered-by')

const swaggerOptions = {
	definition: {
		openapi: '3.0.0',
		info: {
			title: 'API Documentation for Project-G',
			version: '1.0',
			description: 'Documentaion for all endpoints to be used on this API',
		},
		servers: [
			{
				url: 'http://localhost:3000/projectg', //cuando el server este en la nube cambiar esto por la url del servicio
			},
		],
		components: {
			securitySchemes: {
				Bearer: {
					type: 'http',
					scheme: 'bearer',
					bearerFormat: 'JWT',
					description: 'Ingresa el token generado para poder realizar solicitudes',
				},
			},
		},
		security: [
			{
				Bearer: [],
			},
		],
	},
	apis: ['./routes/*.ts'], // Indica la ubicación de tus rutas para generar la documentación
}

const swaggerDocs = swaggerJsdoc(swaggerOptions)

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs))
app.use('/projectg', baseRouter)

app.use((req, res) => {
	res.status(404).send({ error: 'invalid route' })
})

app.get('/', (req, res) => {
	res.send('hola mundo')
})

app.listen(port, () => {
	console.log(`Server running on port ${port}`)
})