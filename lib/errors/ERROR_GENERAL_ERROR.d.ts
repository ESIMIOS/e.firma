import { ERROR_CATEGORY, ERROR_LEVEL } from "./Errors";
export default class ERROR_GENERAL_ERROR extends Error {
    category: ERROR_CATEGORY;
    level: ERROR_LEVEL;
    error: string;
    data: unknown;
    constructor(message: string, data?: any);
}
