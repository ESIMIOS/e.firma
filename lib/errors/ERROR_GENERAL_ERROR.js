"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class ERROR_GENERAL_ERROR extends Error {
    constructor(message, data) {
        super(message);
        this.category = "GENERAL";
        this.level = "ERROR";
        this.error = "ERROR_GENERAL_ERROR";
        this.data = undefined;
        Error.captureStackTrace(this, this.constructor);
        Object.setPrototypeOf(this, ERROR_GENERAL_ERROR.prototype);
        this.name = "ERROR_GENERAL_ERROR";
        this.data = data;
    }
}
exports.default = ERROR_GENERAL_ERROR;
//# sourceMappingURL=ERROR_GENERAL_ERROR.js.map