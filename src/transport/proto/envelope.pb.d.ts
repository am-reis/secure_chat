import * as $protobuf from "protobufjs";
import Long = require("long");

/** Namespace securemessaging. */
export namespace securemessaging {

    /** Namespace v1. */
    namespace v1 {

        /**
         * Properties of a RatchetHeaderProto.
         * @deprecated Use securemessaging.v1.RatchetHeaderProto.$Properties instead.
         */
        interface IRatchetHeaderProto extends securemessaging.v1.RatchetHeaderProto.$Properties {
        }

        /** Represents a RatchetHeaderProto. */
        class RatchetHeaderProto {

            /**
             * Constructs a new RatchetHeaderProto.
             * @param [properties] Properties to set
             */
            constructor(properties?: securemessaging.v1.RatchetHeaderProto.$Properties);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];

            /** RatchetHeaderProto ratchetPublicKey. */
            ratchetPublicKey: Uint8Array;

            /** RatchetHeaderProto previousChainLength. */
            previousChainLength: number;

            /** RatchetHeaderProto messageNumber. */
            messageNumber: number;

            /**
             * Creates a new RatchetHeaderProto instance using the specified properties.
             * @param [properties] Properties to set
             * @returns RatchetHeaderProto instance
             */
            static create(properties: securemessaging.v1.RatchetHeaderProto.$Shape): securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape;
            static create(properties?: securemessaging.v1.RatchetHeaderProto.$Properties): securemessaging.v1.RatchetHeaderProto;

            /**
             * Encodes the specified RatchetHeaderProto message. Does not implicitly {@link securemessaging.v1.RatchetHeaderProto.verify|verify} messages.
             * @param message RatchetHeaderProto message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            static encode(message: securemessaging.v1.RatchetHeaderProto.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified RatchetHeaderProto message, length delimited. Does not implicitly {@link securemessaging.v1.RatchetHeaderProto.verify|verify} messages.
             * @param message RatchetHeaderProto message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            static encodeDelimited(message: securemessaging.v1.RatchetHeaderProto.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a RatchetHeaderProto message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns {securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape} RatchetHeaderProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape;

            /**
             * Decodes a RatchetHeaderProto message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns {securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape} RatchetHeaderProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape;

            /**
             * Verifies a RatchetHeaderProto message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a RatchetHeaderProto message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns RatchetHeaderProto
             */
            static fromObject(object: { [k: string]: any }): securemessaging.v1.RatchetHeaderProto;

            /**
             * Creates a plain object from a RatchetHeaderProto message. Also converts values to other types if specified.
             * @param message RatchetHeaderProto
             * @param [options] Conversion options
             * @returns Plain object
             */
            static toObject(message: securemessaging.v1.RatchetHeaderProto, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this RatchetHeaderProto to JSON.
             * @returns JSON object
             */
            toJSON(): { [k: string]: any };

            /**
             * Gets the type url for RatchetHeaderProto
             * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns The type url
             */
            static getTypeUrl(prefix?: string): string;
        }

        namespace RatchetHeaderProto {

            /** Properties of a RatchetHeaderProto. */
            interface $Properties {

                /** RatchetHeaderProto ratchetPublicKey */
                ratchetPublicKey?: (Uint8Array|null);

                /** RatchetHeaderProto previousChainLength */
                previousChainLength?: (number|null);

                /** RatchetHeaderProto messageNumber */
                messageNumber?: (number|null);

                /** Unknown fields preserved while decoding when enabled */
                $unknowns?: Uint8Array[];
            }

            /** Shape of a RatchetHeaderProto. */
            type $Shape = securemessaging.v1.RatchetHeaderProto.$Properties;
        }

        /** EnvelopeType enum. */
        enum EnvelopeType {

            /** ENVELOPE_TYPE_UNSPECIFIED value */
            ENVELOPE_TYPE_UNSPECIFIED = 0,

            /** SESSION_INIT value */
            SESSION_INIT = 1,

            /** MESSAGE value */
            MESSAGE = 2,

            /** SESSION_RESET value */
            SESSION_RESET = 3
        }

        /**
         * Properties of an EnvelopeProto.
         * @deprecated Use securemessaging.v1.EnvelopeProto.$Properties instead.
         */
        interface IEnvelopeProto extends securemessaging.v1.EnvelopeProto.$Properties {
        }

        /** Represents an EnvelopeProto. */
        class EnvelopeProto {

            /**
             * Constructs a new EnvelopeProto.
             * @param [properties] Properties to set
             */
            constructor(properties?: securemessaging.v1.EnvelopeProto.$Properties);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];

            /** EnvelopeProto type. */
            type: securemessaging.v1.EnvelopeType;

            /** EnvelopeProto protocolVersion. */
            protocolVersion: number;

            /** EnvelopeProto sessionId. */
            sessionId: Uint8Array;

            /** EnvelopeProto ratchetHeader. */
            ratchetHeader?: (securemessaging.v1.RatchetHeaderProto.$Properties|null);

            /** EnvelopeProto ciphertext. */
            ciphertext: Uint8Array;

            /** EnvelopeProto senderIdentityPublicKey. */
            senderIdentityPublicKey: Uint8Array;

            /** EnvelopeProto ephemeralPublicKey. */
            ephemeralPublicKey: Uint8Array;

            /** EnvelopeProto pqCiphertext. */
            pqCiphertext: Uint8Array;

            /** EnvelopeProto signedPrekeyId. */
            signedPrekeyId: number;

            /** EnvelopeProto oneTimePrekeyId. */
            oneTimePrekeyId?: (number|null);

            /** EnvelopeProto pqPrekeyId. */
            pqPrekeyId: number;

            /** EnvelopeProto signature. */
            signature: Uint8Array;

            /**
             * Creates a new EnvelopeProto instance using the specified properties.
             * @param [properties] Properties to set
             * @returns EnvelopeProto instance
             */
            static create(properties: securemessaging.v1.EnvelopeProto.$Shape): securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape;
            static create(properties?: securemessaging.v1.EnvelopeProto.$Properties): securemessaging.v1.EnvelopeProto;

            /**
             * Encodes the specified EnvelopeProto message. Does not implicitly {@link securemessaging.v1.EnvelopeProto.verify|verify} messages.
             * @param message EnvelopeProto message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            static encode(message: securemessaging.v1.EnvelopeProto.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified EnvelopeProto message, length delimited. Does not implicitly {@link securemessaging.v1.EnvelopeProto.verify|verify} messages.
             * @param message EnvelopeProto message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            static encodeDelimited(message: securemessaging.v1.EnvelopeProto.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an EnvelopeProto message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns {securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape} EnvelopeProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape;

            /**
             * Decodes an EnvelopeProto message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns {securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape} EnvelopeProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape;

            /**
             * Verifies an EnvelopeProto message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an EnvelopeProto message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns EnvelopeProto
             */
            static fromObject(object: { [k: string]: any }): securemessaging.v1.EnvelopeProto;

            /**
             * Creates a plain object from an EnvelopeProto message. Also converts values to other types if specified.
             * @param message EnvelopeProto
             * @param [options] Conversion options
             * @returns Plain object
             */
            static toObject(message: securemessaging.v1.EnvelopeProto, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this EnvelopeProto to JSON.
             * @returns JSON object
             */
            toJSON(): { [k: string]: any };

            /**
             * Gets the type url for EnvelopeProto
             * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns The type url
             */
            static getTypeUrl(prefix?: string): string;
        }

        namespace EnvelopeProto {

            /** Properties of an EnvelopeProto. */
            interface $Properties {

                /** EnvelopeProto type */
                type?: (securemessaging.v1.EnvelopeType|null);

                /** EnvelopeProto protocolVersion */
                protocolVersion?: (number|null);

                /** EnvelopeProto sessionId */
                sessionId?: (Uint8Array|null);

                /** EnvelopeProto ratchetHeader */
                ratchetHeader?: (securemessaging.v1.RatchetHeaderProto.$Properties|null);

                /** EnvelopeProto ciphertext */
                ciphertext?: (Uint8Array|null);

                /** EnvelopeProto senderIdentityPublicKey */
                senderIdentityPublicKey?: (Uint8Array|null);

                /** EnvelopeProto ephemeralPublicKey */
                ephemeralPublicKey?: (Uint8Array|null);

                /** EnvelopeProto pqCiphertext */
                pqCiphertext?: (Uint8Array|null);

                /** EnvelopeProto signedPrekeyId */
                signedPrekeyId?: (number|null);

                /** EnvelopeProto oneTimePrekeyId */
                oneTimePrekeyId?: (number|null);

                /** EnvelopeProto pqPrekeyId */
                pqPrekeyId?: (number|null);

                /** EnvelopeProto signature */
                signature?: (Uint8Array|null);

                /** Unknown fields preserved while decoding when enabled */
                $unknowns?: Uint8Array[];
            }

            /** Shape of an EnvelopeProto. */
            type $Shape = securemessaging.v1.EnvelopeProto.$Properties;
        }
    }
}
