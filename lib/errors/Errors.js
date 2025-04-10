"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ERROR_LEVELS = void 0;
exports.isCustomError = isCustomError;
exports.ErrorHandler = ErrorHandler;
exports.ERROR_LEVELS = Object.freeze({
    FATAL: 0,
    ERROR: 1,
    WARN: 2,
    INFO: 3,
    DEBUG: 4,
    TRACE: 5,
});
function isCustomError(object) {
    return (Object.prototype.hasOwnProperty.call(object, "category") &&
        Object.prototype.hasOwnProperty.call(object, "level") &&
        Object.prototype.hasOwnProperty.call(object, "error") &&
        Object.prototype.hasOwnProperty.call(object, "data"));
}
function ErrorHandler(e) {
    if (isCustomError(e)) {
        console.log("Custom error:", e.error);
        if (e.callback) {
            e.callback();
        }
        else {
            console.log("category:", e.category);
            console.log("error:", e.error);
            console.log("level:", e.level);
            console.log("data:", e.data);
        }
    }
    else {
        console.error("On ErrorHandler:", e);
    }
}
//# sourceMappingURL=Errors.js.map