import JWT
import Vapor
import JWTService

final class FakeJWTServiceDelegate: JWTServiceDelegate {
    var keyCalls: [String] = []
    var keyStub: ((String) -> JWTSigner?)?

    func key(for recipient: String) -> JWTSigner? {
        keyCalls.append(recipient)
        return keyStub?(recipient)
    }

    var validateCalls: [String] = []
    var validateStub: ((String) -> Bool)?
    func validate(sender: String) -> Bool {
        validateCalls.append(sender)
        return validateStub!(sender)
    }
}
