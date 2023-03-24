"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GlobalMethods = void 0;
const node_forge_1 = require("node-forge");
const ERROR_GENERAL_ERROR_1 = __importDefault(require("./errors/ERROR_GENERAL_ERROR"));
class GlobalMethods {
    constructor() { }
    static hash(input, algorithm = 'sha256', returnForgeHashObject = false, encoding) {
        const mdObj = node_forge_1.md[algorithm].create();
        if (encoding) {
            mdObj.update(input, encoding);
        }
        else {
            mdObj.update(input);
        }
        if (returnForgeHashObject) {
            return mdObj;
        }
        return mdObj.digest().toHex();
    }
    static readASN1(file) {
        try {
            const ans1Object = node_forge_1.asn1.fromDer(file);
            return ans1Object;
        }
        catch (err) {
            throw new ERROR_GENERAL_ERROR_1.default('Verifique el archivo, no fue posible decodificar el ANS1');
        }
    }
    static binaryToBase64(binary) {
        return node_forge_1.util.encode64(binary);
    }
    static base64ToBinary(base64String) {
        return node_forge_1.util.decode64(base64String);
    }
}
exports.GlobalMethods = GlobalMethods;
//# sourceMappingURL=GlobalMethods.js.map