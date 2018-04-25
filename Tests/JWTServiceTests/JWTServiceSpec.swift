import Quick
import Nimble

import JWTService

import VaporTestHelpers
@testable import Vapor
@testable import JWT

final class JWTServiceSpec: QuickSpec {
    override func spec() {
        var subject: JWTService!

        let hs256Signer = JWTSigner.hs256(key: Data("secret".utf8))
        var fakeDelegate: FakeJWTServiceDelegate!

        var client: TestClient!

        beforeEach {
            fakeDelegate = FakeJWTServiceDelegate()
            subject = DefaultJWTService(
                decoder: hs256Signer,
                delegate: fakeDelegate,
                identifier: "test"
            )

            fakeDelegate.validateStub = { _ in return true }

            client = try! TestApp(routeRegister: {_ in }).client
        }

        describe("decode(:)") {
            describe("with a valid token") {
                let token = Token(
                    from: "from",
                    to: "test"
                )

                var jwt = JWT(payload: token)
                let data = try! jwt.sign(using: hs256Signer)
                let stringData = String(data: data, encoding: .utf8)!

                it("correctly decodes the user") {
                    let request = client.makeRequest(method: .GET, headers: ["authorization": "bearer \(stringData)"])
                    let decoded: Token
                    do {
                        decoded = try subject.decode(request)
                    } catch let error {
                        expect(error).to(beNil())
                        return
                    }

                    expect(decoded) == token
                }
            }

            describe("with a token to the wrong service") {
                let user = Token(
                    from: "from",
                    to: "someone else"
                )

                var jwt = JWT(payload: user)
                let data = try! jwt.sign(using: hs256Signer)
                let token = String(data: data, encoding: .utf8)!

                it("throws an unauthorized error") {
                    let request = client.makeRequest(method: .GET, headers: ["authorization": "bearer \(token)"])
                    expect { try subject.decode(request) as Token }.to(throwError(closure: { error in
                        guard let abort = error as? Abort else {
                            expect(error).to(beAKindOf(Abort.self))
                            return
                        }

                        expect(abort.status) == HTTPResponseStatus.unauthorized
                    }))
                }
            }

            describe("with a token from a service not authorized to talk to us") {
                let user = Token(
                    from: "bad sender",
                    to: "test"
                )

                var jwt = JWT(payload: user)
                let data = try! jwt.sign(using: hs256Signer)
                let token = String(data: data, encoding: .utf8)!

                it("throws an unauthorized error") {
                    fakeDelegate.validateStub = { _ in return false }

                    let request = client.makeRequest(method: .GET, headers: ["authorization": "bearer \(token)"])
                    expect { try subject.decode(request) as Token }.to(throwError(closure: { error in
                        guard let abort = error as? Abort else {
                            expect(error).to(beAKindOf(Abort.self))
                            return
                        }

                        expect(abort.status) == HTTPResponseStatus.unauthorized
                    }))
                }
            }

            describe("if no authorization: bearer header is present in the request") {
                it("throws an unauthorized error") {
                    let request = client.makeRequest(method: .GET, headers: ["authorization": "token foo"])

                    expect { try subject.decode(request) as Token }.to(throwError(closure: { error in
                        guard let abort = error as? Abort else {
                            expect(error).to(beAKindOf(Abort.self))
                            return
                        }

                        expect(abort.status) == HTTPResponseStatus.unauthorized
                    }))
                }
            }

            describe("if no authorization header is present in the request") {
                it("throws an unauthorized error") {
                    let request = client.makeRequest(method: .GET)

                    expect { try subject.decode(request) as Token }.to(throwError(closure: { error in
                        guard let abort = error as? Abort else {
                            expect(error).to(beAKindOf(Abort.self))
                            return
                        }

                        expect(abort.status) == HTTPResponseStatus.unauthorized
                    }))
                }
            }
        }

        describe("encode(:to:)") {
            let factory = { from in
                return Token(from: from, to: "receiver")
            }

            describe("when the delegate knows the recipient's key") {
                beforeEach {
                    fakeDelegate.keyStub = { _ in return hs256Signer }
                }

                it("doesn't throw") {
                    expect { try subject.encode(factory) }.toNot(throwError())
                }

                it("encodes the payload with the key from the delegate") {
                    guard let data = try? subject.encode(factory) else {
                        fail("throwed when encoding data")
                        return
                    }

                    let value: Token = (try! JWT(from: data, verifiedUsing: hs256Signer)).payload

                    expect(value.from) == "test"
                    expect(value.to) == "receiver"
                }
            }

            describe("when the delegate doesn't know the recipient's key") {
                beforeEach {
                    fakeDelegate.keyStub = { _ in nil }
                }

                it("raises an error") {
                    expect { try subject.encode(factory) }.to(throwError())
                }
            }
        }
    }
}

final class StaticJWTServiceDelegateSpec: QuickSpec {
    override func spec() {
        var subject: StaticJWTServiceDelegate!

        beforeEach {
            subject = StaticJWTServiceDelegate(
                publicKeys: [
                    "foo": try! JWTSigner.rs256(key: .public(pem: rsaPublicKey))
                ],
                allowedSenders: [
                    "foo",
                    "bar"
                ]
            )
        }

        describe("key(for:)") {
            it("returns the RSA key if we have a key for the recipient") {
                expect(subject.key(for: "foo")).toNot(beNil())

                guard let receivedKey = subject.key(for: "foo") else {
                    fail("didn't get key for subject")
                    return
                }

                let key = try! JWTSigner.rs256(key: .private(pem: rsaPrivateKey))

                var payload = JWT(payload: Token(from: "hello", to: "world"))

                let data = try! payload.sign(using: key)

                let publicVerified = try! JWT<Token>(from: data, verifiedUsing: receivedKey)

                expect(publicVerified.payload.from) == "hello"
                expect(publicVerified.payload.to) == "world"
            }

            it("returns nil if nothing exists for that recipient") {
                expect(subject.key(for: "baz")).to(beNil())
            }
        }

        describe("validate(sender:)") {
            describe("when the allowedSenders is not nil") {
                it("allows anyone on the allowSenders list") {
                    expect(subject.validate(sender: "foo")) == true
                    expect(subject.validate(sender: "bar")) == true
                }

                it("rejects anyone not on the allowedSenders list") {
                    expect(subject.validate(sender: "someone else")) == false
                }
            }

            describe("when the allowedSenders is nil") {
                beforeEach {
                    subject = StaticJWTServiceDelegate(
                        publicKeys: [:],
                        allowedSenders: nil
                    )
                }

                it("does not validation and allows everything through") {
                    expect(subject.validate(sender: "who cares?")) == true
                }
            }
        }
    }
}

struct Token: Payload, Equatable {
    func verify() throws {}
    let from: String
    let to: String
}
