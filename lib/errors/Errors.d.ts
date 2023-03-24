export type ERROR_CATEGORY = 'GENERAL' | 'AUTHORIZATION' | 'ROUTES';
export type ERROR_LEVEL = 'FATAL' | 'ERROR' | 'WARN' | 'INFO' | 'DEBUG' | 'TRACE';
export declare const ERROR_LEVELS: Readonly<{
    FATAL: 0;
    ERROR: 1;
    WARN: 2;
    INFO: 3;
    DEBUG: 4;
    TRACE: 5;
}>;
export interface CustomError {
    message: string;
    category: ERROR_CATEGORY;
    level: ERROR_LEVEL;
    error: string;
    data?: unknown;
    callback?(): void;
}
export declare function isCustomError(object: unknown): object is CustomError;
export declare function ErrorHandler(e: Error | CustomError): void;
