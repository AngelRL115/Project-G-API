import { createLogger, format, transports } from 'winston'

// Configuración de Winston
const logger = createLogger({
    level: 'info', // Nivel de logging (info, warn, error, debug, etc.)
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`
        })
    ),
    transports: [
        // Registro en consola
        new transports.Console(),
        // Registro en archivo
        new transports.File({ filename: 'logs/app.log' }),
        // Archivo separado para errores
        new transports.File({ filename: 'logs/errors.log', level: 'error' }),
    ],
})
export const morganStream = {
    write: (message: string) => logger.http(message.trim()),
}
// Exporta el logger para usarlo en toda la aplicación
export default logger