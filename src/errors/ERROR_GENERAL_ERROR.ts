import { ERROR_CATEGORY, ERROR_LEVEL } from './Errors'

export default class ERROR_GENERAL_ERROR extends Error {
	category = 'GENERAL' as ERROR_CATEGORY
	level = 'ERROR' as ERROR_LEVEL
	error = 'ERROR_GENERAL_ERROR'
	data: unknown = undefined
	constructor(message: string, data?: any) {
		super(message)
		Error.captureStackTrace(this, this.constructor)
		Object.setPrototypeOf(this, ERROR_GENERAL_ERROR.prototype)
		this.name = 'ERROR_GENERAL_ERROR'
		this.data = data
	}
}
