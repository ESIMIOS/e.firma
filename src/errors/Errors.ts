export type ERROR_CATEGORY = "GENERAL" | "AUTHORIZATION" | "ROUTES";

export type ERROR_LEVEL =
  | "FATAL"
  | "ERROR"
  | "WARN"
  | "INFO"
  | "DEBUG"
  | "TRACE";

export const ERROR_LEVELS = Object.freeze({
  FATAL: 0,
  ERROR: 1,
  WARN: 2,
  INFO: 3,
  DEBUG: 4,
  TRACE: 5,
});

/**
 * Syslog standar
 * FATAL    One or more key business functionalities are not working and the whole system doesn’t fulfill the business functionalities
 * ERROR    One or more functionalities are not working, preventing some functionalities from working correctly
 * WARN     Unexpected behavior happened inside the application, but it is continuing its work and the key business features are operating as expected.
 * INFO     An event happened, the event is purely informative and can be ignored during normal operations.
 * DEBUG    A log level used for events considered to be useful during software debugging when more granular information is needed.
 * TRACE    A log level describing events showing step by step execution of your code that can be ignored during the standard operation, but may be useful during extended debugging sessions.
 */

export interface CustomError extends Error {
  category: ERROR_CATEGORY;
  level: ERROR_LEVEL;
  error: string;
  data?: unknown;
  callback?(): void;
}
//Definir errores organizados por categoría

export function isCustomError(object: unknown): object is CustomError {
  return (
    Object.prototype.hasOwnProperty.call(object, "category") &&
    Object.prototype.hasOwnProperty.call(object, "level") &&
    Object.prototype.hasOwnProperty.call(object, "error") &&
    Object.prototype.hasOwnProperty.call(object, "data")
  );
}

export function ErrorHandler(e: Error | CustomError) {
  if (isCustomError(e)) {
    console.log("Custom error:", e.error);
    if (e.callback) {
      e.callback();
    } else {
      console.log("category:", e.category);
      console.log("error:", e.error);
      console.log("level:", e.level);
      console.log("data:", e.data);
    }
  } else {
    console.error("On ErrorHandler:", e);
  }
}
