import { ERROR_CATEGORY, ERROR_LEVEL, CustomError } from './Errors'

export default class ERROR_GENERAL_ERROR extends Error implements CustomError {
	category = 'GENERAL' as ERROR_CATEGORY
	level = 'ERROR' as ERROR_LEVEL
	error = 'ERROR_GENERAL_ERROR'
	data: unknown = undefined
	constructor(message: string, data?: any) {
		super(message)
		this.data = data
		console.error(message)
	}
}
