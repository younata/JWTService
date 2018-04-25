import JWT
import Vapor
import Foundation

public protocol Payload: JWTPayload {
    var from: String { get }
    var to: String { get }
}

public protocol JWTServiceDelegate {
    // nil means we're not supposed to talk to this service.
    func key(for recipient: String) -> JWTSigner?

    // Whether the sender is allowed to talk to this service.
    func validate(sender: String) -> Bool
}

public protocol JWTService {
    var delegate: JWTServiceDelegate { get }

    func decode<T: Payload>(_ request: Request) throws -> T
    func encode<T: Payload>(_ payload: @escaping (String) -> T) throws -> Data
}

public struct DefaultJWTService: JWTService {
    public let decoder: JWTSigner
    public var delegate: JWTServiceDelegate
    public let identifier: String

    public init(
        decoder: JWTSigner,
        delegate: JWTServiceDelegate,
        identifier: String
        ) {
        self.decoder = decoder
        self.delegate = delegate
        self.identifier = identifier
    }

    public func decode<T>(_ request: Request) throws -> T where T : Payload {
        let authorizationHeaders = request.http.headers["authorization"]
        guard !authorizationHeaders.isEmpty else {
            throw Abort(.unauthorized)
        }

        guard let authorization = authorizationHeaders.filter({ $0.lowercased().hasPrefix("bearer ") }).first else {
            throw Abort(.unauthorized)
        }

        let token = String(authorization.dropFirst("bearer ".count))

        let payload: T = (try JWT(from: token, verifiedUsing: self.decoder)).payload
        guard payload.to == identifier && self.delegate.validate(sender: payload.from) else {
            throw Abort(.unauthorized)
        }
        return payload
    }

    public func encode<T>(_ payload: @escaping (String) -> T) throws -> Data where T : Payload {
        let token = payload(self.identifier)
        guard let key = self.delegate.key(for: token.to) else {
            throw Abort(.forbidden)
        }

        var jwt = JWT(payload: token)
        return try jwt.sign(using: key)
    }
}

public struct StaticJWTServiceDelegate: JWTServiceDelegate {
    public let publicKeys: [String: JWTSigner]
    public let allowedSenders: Set<String>?

    public init(publicKeys: [String: JWTSigner], allowedSenders: Set<String>?) {
        self.publicKeys = publicKeys
        self.allowedSenders = allowedSenders
    }

    public func key(for recipient: String) -> JWTSigner? {
        return self.publicKeys[recipient]
    }

    public func validate(sender: String) -> Bool {
        guard let allowedSenders = self.allowedSenders else {
            return true
        }
        return allowedSenders.contains(sender)
    }
}

