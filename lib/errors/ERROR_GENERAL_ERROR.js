"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class ERROR_GENERAL_ERROR extends Error {
    constructor(message, data) {
        super(message);
        this.category = 'GENERAL';
        this.level = 'ERROR';
        this.error = 'ERROR_GENERAL_ERROR';
        this.data = undefined;
        this.data = data;
        console.error(message);
    }
}
exports.default = ERROR_GENERAL_ERROR;
//# sourceMappingURL=ERROR_GENERAL_ERROR.js.map