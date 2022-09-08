import winston from "winston"

let myFormat = winston.format.combine(
	winston.format.timestamp({
		format: "YYYY-MM-DD HH:mm:ss",
	}),
	winston.format.printf((info) => {
		return `[${info.timestamp}] - [${info.level.toUpperCase()}] - ${
			info.message
		}`
	})
)

const logger = winston.createLogger({
	level: "info",
	format: myFormat,
	transports: [
		new winston.transports.File({
			filename: "./Logger/logger.log",
			level: "error",
		}),
		new winston.transports.Console({ level: "silly" }),
	],
})
export default logger
