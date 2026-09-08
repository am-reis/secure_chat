/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-mixed-operators, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars, default-case, jsdoc/require-param*/
import $protobuf from "protobufjs/minimal.js";

// Common aliases
const $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;
const $Object = $util.global.Object, $undefined = $util.global.undefined, $Error = $util.global.Error, $RangeError = $util.global.RangeError, $TypeError = $util.global.TypeError, $Number = $util.global.Number, $String = $util.global.String, $Array = $util.global.Array;

// Exported root namespace
const $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

export const securemessaging = $root.securemessaging = (() => {

    /**
     * Namespace securemessaging.
     * @exports securemessaging
     * @namespace
     */
    const securemessaging = {};

    securemessaging.v1 = (function() {

        /**
         * Namespace v1.
         * @memberof securemessaging
         * @namespace
         */
        const v1 = {};

        v1.RatchetHeaderProto = (function() {

            /**
             * Properties of a RatchetHeaderProto.
             * @typedef {Object} securemessaging.v1.RatchetHeaderProto.$Properties
             * @property {Uint8Array|null} [ratchetPublicKey] RatchetHeaderProto ratchetPublicKey
             * @property {number|null} [previousChainLength] RatchetHeaderProto previousChainLength
             * @property {number|null} [messageNumber] RatchetHeaderProto messageNumber
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RatchetHeaderProto.
             * @memberof securemessaging.v1
             * @interface IRatchetHeaderProto
             * @augments securemessaging.v1.RatchetHeaderProto.$Properties
             * @deprecated Use securemessaging.v1.RatchetHeaderProto.$Properties instead.
             */

            /**
             * Shape of a RatchetHeaderProto.
             * @typedef {securemessaging.v1.RatchetHeaderProto.$Properties} securemessaging.v1.RatchetHeaderProto.$Shape
             */

            /**
             * Constructs a new RatchetHeaderProto.
             * @memberof securemessaging.v1
             * @classdesc Represents a RatchetHeaderProto.
             * @constructor
             * @param {securemessaging.v1.RatchetHeaderProto.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RatchetHeaderProto = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RatchetHeaderProto ratchetPublicKey.
             * @member {Uint8Array} ratchetPublicKey
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @instance
             */
            RatchetHeaderProto.prototype.ratchetPublicKey = $util.newBuffer([]);

            /**
             * RatchetHeaderProto previousChainLength.
             * @member {number} previousChainLength
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @instance
             */
            RatchetHeaderProto.prototype.previousChainLength = 0;

            /**
             * RatchetHeaderProto messageNumber.
             * @member {number} messageNumber
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @instance
             */
            RatchetHeaderProto.prototype.messageNumber = 0;

            /**
             * Creates a new RatchetHeaderProto instance using the specified properties.
             * @function create
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {securemessaging.v1.RatchetHeaderProto.$Properties=} [properties] Properties to set
             * @returns {securemessaging.v1.RatchetHeaderProto} RatchetHeaderProto instance
             * @type {{
             *   (properties: securemessaging.v1.RatchetHeaderProto.$Shape): securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape;
             *   (properties?: securemessaging.v1.RatchetHeaderProto.$Properties): securemessaging.v1.RatchetHeaderProto;
             * }}
             */
            RatchetHeaderProto.create = function(properties) {
                return new RatchetHeaderProto(properties);
            };

            /**
             * Encodes the specified RatchetHeaderProto message. Does not implicitly {@link securemessaging.v1.RatchetHeaderProto.verify|verify} messages.
             * @function encode
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {securemessaging.v1.RatchetHeaderProto.$Properties} message RatchetHeaderProto message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RatchetHeaderProto.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.ratchetPublicKey != null && $Object.hasOwnProperty.call(message, "ratchetPublicKey") && message.ratchetPublicKey.length)
                    writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.ratchetPublicKey);
                if (message.previousChainLength != null && $Object.hasOwnProperty.call(message, "previousChainLength") && message.previousChainLength !== 0)
                    writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.previousChainLength);
                if (message.messageNumber != null && $Object.hasOwnProperty.call(message, "messageNumber") && message.messageNumber !== 0)
                    writer.uint32(/* id 3, wireType 0 =*/24).uint32(message.messageNumber);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RatchetHeaderProto message, length delimited. Does not implicitly {@link securemessaging.v1.RatchetHeaderProto.verify|verify} messages.
             * @function encodeDelimited
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {securemessaging.v1.RatchetHeaderProto.$Properties} message RatchetHeaderProto message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RatchetHeaderProto.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RatchetHeaderProto message from the specified reader or buffer.
             * @function decode
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape} RatchetHeaderProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RatchetHeaderProto.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end, message, value;
                if (length === $undefined)
                    end = reader.len;
                else {
                    end = reader.pos + length;
                    if (end > reader.len)
                        throw $RangeError("index out of range");
                    length = reader.len;
                    reader.len = end;
                }
                message = _target || new $root.securemessaging.v1.RatchetHeaderProto();
                while (reader.pos < end) {
                    let start = reader.pos;
                    let tag = reader.tag();
                    if (tag === _end) {
                        _end = $undefined;
                        break;
                    }
                    let wireType = tag & 7;
                    switch (tag >>>= 3) {
                    case 1: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.bytes()).length)
                                message.ratchetPublicKey = value;
                            else
                                delete message.ratchetPublicKey;
                            continue;
                        }
                    case 2: {
                            if (wireType !== 0)
                                break;
                            if (value = reader.uint32())
                                message.previousChainLength = value;
                            else
                                delete message.previousChainLength;
                            continue;
                        }
                    case 3: {
                            if (wireType !== 0)
                                break;
                            if (value = reader.uint32())
                                message.messageNumber = value;
                            else
                                delete message.messageNumber;
                            continue;
                        }
                    }
                    reader.skipType(wireType, _depth, tag);
                    if (!reader.discardUnknown) {
                        $util.makeProp(message, "$unknowns", false);
                        (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                    }
                }
                if (length !== $undefined) {
                    if (reader.pos !== end)
                        throw $RangeError("index out of range");
                    reader.len = length;
                }
                if (_end !== $undefined)
                    throw $Error("missing end group");
                return message;
            };

            /**
             * Decodes a RatchetHeaderProto message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {securemessaging.v1.RatchetHeaderProto & securemessaging.v1.RatchetHeaderProto.$Shape} RatchetHeaderProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RatchetHeaderProto.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RatchetHeaderProto message.
             * @function verify
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RatchetHeaderProto.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.ratchetPublicKey != null && $Object.hasOwnProperty.call(message, "ratchetPublicKey"))
                    if (!(message.ratchetPublicKey && typeof message.ratchetPublicKey.length === "number" || $util.isString(message.ratchetPublicKey)))
                        return "ratchetPublicKey: buffer expected";
                if (message.previousChainLength != null && $Object.hasOwnProperty.call(message, "previousChainLength"))
                    if (!$util.isInteger(message.previousChainLength))
                        return "previousChainLength: integer expected";
                if (message.messageNumber != null && $Object.hasOwnProperty.call(message, "messageNumber"))
                    if (!$util.isInteger(message.messageNumber))
                        return "messageNumber: integer expected";
                return null;
            };

            /**
             * Creates a RatchetHeaderProto message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {securemessaging.v1.RatchetHeaderProto} RatchetHeaderProto
             */
            RatchetHeaderProto.fromObject = function (object, _depth) {
                if (object instanceof $root.securemessaging.v1.RatchetHeaderProto)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".securemessaging.v1.RatchetHeaderProto: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.securemessaging.v1.RatchetHeaderProto();
                if (object.ratchetPublicKey != null)
                    if (object.ratchetPublicKey.length)
                        if (typeof object.ratchetPublicKey === "string")
                            $util.base64.decode(object.ratchetPublicKey, message.ratchetPublicKey = $util.newBuffer($util.base64.length(object.ratchetPublicKey)), 0);
                        else if (object.ratchetPublicKey.length >= 0)
                            message.ratchetPublicKey = object.ratchetPublicKey;
                if (object.previousChainLength != null)
                    if ($Number(object.previousChainLength) !== 0)
                        message.previousChainLength = object.previousChainLength >>> 0;
                if (object.messageNumber != null)
                    if ($Number(object.messageNumber) !== 0)
                        message.messageNumber = object.messageNumber >>> 0;
                return message;
            };

            /**
             * Creates a plain object from a RatchetHeaderProto message. Also converts values to other types if specified.
             * @function toObject
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {securemessaging.v1.RatchetHeaderProto} message RatchetHeaderProto
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RatchetHeaderProto.toObject = function (message, options, _depth) {
                if (!options)
                    options = {};
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    if (options.bytes === $String)
                        object.ratchetPublicKey = "";
                    else {
                        object.ratchetPublicKey = [];
                        if (options.bytes !== $Array)
                            object.ratchetPublicKey = $util.newBuffer(object.ratchetPublicKey);
                    }
                    object.previousChainLength = 0;
                    object.messageNumber = 0;
                }
                if (message.ratchetPublicKey != null && $Object.hasOwnProperty.call(message, "ratchetPublicKey"))
                    object.ratchetPublicKey = options.bytes === $String ? $util.base64.encode(message.ratchetPublicKey, 0, message.ratchetPublicKey.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.ratchetPublicKey) : message.ratchetPublicKey;
                if (message.previousChainLength != null && $Object.hasOwnProperty.call(message, "previousChainLength"))
                    object.previousChainLength = message.previousChainLength;
                if (message.messageNumber != null && $Object.hasOwnProperty.call(message, "messageNumber"))
                    object.messageNumber = message.messageNumber;
                return object;
            };

            /**
             * Converts this RatchetHeaderProto to JSON.
             * @function toJSON
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RatchetHeaderProto.prototype.toJSON = function() {
                return RatchetHeaderProto.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RatchetHeaderProto
             * @function getTypeUrl
             * @memberof securemessaging.v1.RatchetHeaderProto
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RatchetHeaderProto.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/securemessaging.v1.RatchetHeaderProto";
            };

            return RatchetHeaderProto;
        })();

        /**
         * EnvelopeType enum.
         * @name securemessaging.v1.EnvelopeType
         * @enum {number}
         * @property {number} ENVELOPE_TYPE_UNSPECIFIED=0 ENVELOPE_TYPE_UNSPECIFIED value
         * @property {number} SESSION_INIT=1 SESSION_INIT value
         * @property {number} MESSAGE=2 MESSAGE value
         * @property {number} SESSION_RESET=3 SESSION_RESET value
         */
        v1.EnvelopeType = (function() {
            const valuesById = $Object.create(null), values = $Object.create(valuesById);
            values[valuesById[0] = "ENVELOPE_TYPE_UNSPECIFIED"] = 0;
            values[valuesById[1] = "SESSION_INIT"] = 1;
            values[valuesById[2] = "MESSAGE"] = 2;
            values[valuesById[3] = "SESSION_RESET"] = 3;
            return values;
        })();

        v1.EnvelopeProto = (function() {

            /**
             * Properties of an EnvelopeProto.
             * @typedef {Object} securemessaging.v1.EnvelopeProto.$Properties
             * @property {securemessaging.v1.EnvelopeType|null} [type] EnvelopeProto type
             * @property {number|null} [protocolVersion] EnvelopeProto protocolVersion
             * @property {Uint8Array|null} [sessionId] EnvelopeProto sessionId
             * @property {securemessaging.v1.RatchetHeaderProto.$Properties|null} [ratchetHeader] EnvelopeProto ratchetHeader
             * @property {Uint8Array|null} [ciphertext] EnvelopeProto ciphertext
             * @property {Uint8Array|null} [senderIdentityPublicKey] EnvelopeProto senderIdentityPublicKey
             * @property {Uint8Array|null} [ephemeralPublicKey] EnvelopeProto ephemeralPublicKey
             * @property {Uint8Array|null} [pqCiphertext] EnvelopeProto pqCiphertext
             * @property {number|null} [signedPrekeyId] EnvelopeProto signedPrekeyId
             * @property {number|null} [oneTimePrekeyId] EnvelopeProto oneTimePrekeyId
             * @property {number|null} [pqPrekeyId] EnvelopeProto pqPrekeyId
             * @property {Uint8Array|null} [signature] EnvelopeProto signature
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of an EnvelopeProto.
             * @memberof securemessaging.v1
             * @interface IEnvelopeProto
             * @augments securemessaging.v1.EnvelopeProto.$Properties
             * @deprecated Use securemessaging.v1.EnvelopeProto.$Properties instead.
             */

            /**
             * Shape of an EnvelopeProto.
             * @typedef {securemessaging.v1.EnvelopeProto.$Properties} securemessaging.v1.EnvelopeProto.$Shape
             */

            /**
             * Constructs a new EnvelopeProto.
             * @memberof securemessaging.v1
             * @classdesc Represents an EnvelopeProto.
             * @constructor
             * @param {securemessaging.v1.EnvelopeProto.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const EnvelopeProto = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * EnvelopeProto type.
             * @member {securemessaging.v1.EnvelopeType} type
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.type = 0;

            /**
             * EnvelopeProto protocolVersion.
             * @member {number} protocolVersion
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.protocolVersion = 0;

            /**
             * EnvelopeProto sessionId.
             * @member {Uint8Array} sessionId
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.sessionId = $util.newBuffer([]);

            /**
             * EnvelopeProto ratchetHeader.
             * @member {securemessaging.v1.RatchetHeaderProto.$Properties|null|undefined} ratchetHeader
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.ratchetHeader = null;

            /**
             * EnvelopeProto ciphertext.
             * @member {Uint8Array} ciphertext
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.ciphertext = $util.newBuffer([]);

            /**
             * EnvelopeProto senderIdentityPublicKey.
             * @member {Uint8Array} senderIdentityPublicKey
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.senderIdentityPublicKey = $util.newBuffer([]);

            /**
             * EnvelopeProto ephemeralPublicKey.
             * @member {Uint8Array} ephemeralPublicKey
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.ephemeralPublicKey = $util.newBuffer([]);

            /**
             * EnvelopeProto pqCiphertext.
             * @member {Uint8Array} pqCiphertext
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.pqCiphertext = $util.newBuffer([]);

            /**
             * EnvelopeProto signedPrekeyId.
             * @member {number} signedPrekeyId
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.signedPrekeyId = 0;

            /**
             * EnvelopeProto oneTimePrekeyId.
             * @member {number|null|undefined} oneTimePrekeyId
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.oneTimePrekeyId = null;

            /**
             * EnvelopeProto pqPrekeyId.
             * @member {number} pqPrekeyId
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.pqPrekeyId = 0;

            /**
             * EnvelopeProto signature.
             * @member {Uint8Array} signature
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             */
            EnvelopeProto.prototype.signature = $util.newBuffer([]);

            // OneOf field names bound to virtual getters and setters
            let $oneOfFields;

            // Virtual OneOf for proto3 optional field
            $Object.defineProperty(EnvelopeProto.prototype, "_oneTimePrekeyId", {
                get: $util.oneOfGetter($oneOfFields = ["oneTimePrekeyId"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            /**
             * Creates a new EnvelopeProto instance using the specified properties.
             * @function create
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {securemessaging.v1.EnvelopeProto.$Properties=} [properties] Properties to set
             * @returns {securemessaging.v1.EnvelopeProto} EnvelopeProto instance
             * @type {{
             *   (properties: securemessaging.v1.EnvelopeProto.$Shape): securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape;
             *   (properties?: securemessaging.v1.EnvelopeProto.$Properties): securemessaging.v1.EnvelopeProto;
             * }}
             */
            EnvelopeProto.create = function(properties) {
                return new EnvelopeProto(properties);
            };

            /**
             * Encodes the specified EnvelopeProto message. Does not implicitly {@link securemessaging.v1.EnvelopeProto.verify|verify} messages.
             * @function encode
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {securemessaging.v1.EnvelopeProto.$Properties} message EnvelopeProto message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            EnvelopeProto.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.type != null && $Object.hasOwnProperty.call(message, "type") && message.type !== 0)
                    writer.uint32(/* id 1, wireType 0 =*/8).int32(message.type);
                if (message.protocolVersion != null && $Object.hasOwnProperty.call(message, "protocolVersion") && message.protocolVersion !== 0)
                    writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.protocolVersion);
                if (message.sessionId != null && $Object.hasOwnProperty.call(message, "sessionId") && message.sessionId.length)
                    writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.sessionId);
                if (message.ratchetHeader != null && $Object.hasOwnProperty.call(message, "ratchetHeader"))
                    $root.securemessaging.v1.RatchetHeaderProto.encode(message.ratchetHeader, writer.uint32(/* id 4, wireType 2 =*/34).fork(), _depth + 1).ldelim();
                if (message.ciphertext != null && $Object.hasOwnProperty.call(message, "ciphertext") && message.ciphertext.length)
                    writer.uint32(/* id 5, wireType 2 =*/42).bytes(message.ciphertext);
                if (message.senderIdentityPublicKey != null && $Object.hasOwnProperty.call(message, "senderIdentityPublicKey") && message.senderIdentityPublicKey.length)
                    writer.uint32(/* id 6, wireType 2 =*/50).bytes(message.senderIdentityPublicKey);
                if (message.ephemeralPublicKey != null && $Object.hasOwnProperty.call(message, "ephemeralPublicKey") && message.ephemeralPublicKey.length)
                    writer.uint32(/* id 7, wireType 2 =*/58).bytes(message.ephemeralPublicKey);
                if (message.pqCiphertext != null && $Object.hasOwnProperty.call(message, "pqCiphertext") && message.pqCiphertext.length)
                    writer.uint32(/* id 8, wireType 2 =*/66).bytes(message.pqCiphertext);
                if (message.signedPrekeyId != null && $Object.hasOwnProperty.call(message, "signedPrekeyId") && message.signedPrekeyId !== 0)
                    writer.uint32(/* id 9, wireType 0 =*/72).uint32(message.signedPrekeyId);
                if (message.oneTimePrekeyId != null && $Object.hasOwnProperty.call(message, "oneTimePrekeyId"))
                    writer.uint32(/* id 10, wireType 0 =*/80).uint32(message.oneTimePrekeyId);
                if (message.pqPrekeyId != null && $Object.hasOwnProperty.call(message, "pqPrekeyId") && message.pqPrekeyId !== 0)
                    writer.uint32(/* id 11, wireType 0 =*/88).uint32(message.pqPrekeyId);
                if (message.signature != null && $Object.hasOwnProperty.call(message, "signature") && message.signature.length)
                    writer.uint32(/* id 12, wireType 2 =*/98).bytes(message.signature);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified EnvelopeProto message, length delimited. Does not implicitly {@link securemessaging.v1.EnvelopeProto.verify|verify} messages.
             * @function encodeDelimited
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {securemessaging.v1.EnvelopeProto.$Properties} message EnvelopeProto message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            EnvelopeProto.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes an EnvelopeProto message from the specified reader or buffer.
             * @function decode
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape} EnvelopeProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            EnvelopeProto.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end, message, value;
                if (length === $undefined)
                    end = reader.len;
                else {
                    end = reader.pos + length;
                    if (end > reader.len)
                        throw $RangeError("index out of range");
                    length = reader.len;
                    reader.len = end;
                }
                message = _target || new $root.securemessaging.v1.EnvelopeProto();
                while (reader.pos < end) {
                    let start = reader.pos;
                    let tag = reader.tag();
                    if (tag === _end) {
                        _end = $undefined;
                        break;
                    }
                    let wireType = tag & 7;
                    switch (tag >>>= 3) {
                    case 1: {
                            if (wireType !== 0)
                                break;
                            if (value = reader.int32())
                                message.type = value;
                            else
                                delete message.type;
                            continue;
                        }
                    case 2: {
                            if (wireType !== 0)
                                break;
                            if (value = reader.uint32())
                                message.protocolVersion = value;
                            else
                                delete message.protocolVersion;
                            continue;
                        }
                    case 3: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.bytes()).length)
                                message.sessionId = value;
                            else
                                delete message.sessionId;
                            continue;
                        }
                    case 4: {
                            if (wireType !== 2)
                                break;
                            message.ratchetHeader = $root.securemessaging.v1.RatchetHeaderProto.decode(reader, reader.uint32(), $undefined, _depth + 1, message.ratchetHeader);
                            continue;
                        }
                    case 5: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.bytes()).length)
                                message.ciphertext = value;
                            else
                                delete message.ciphertext;
                            continue;
                        }
                    case 6: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.bytes()).length)
                                message.senderIdentityPublicKey = value;
                            else
                                delete message.senderIdentityPublicKey;
                            continue;
                        }
                    case 7: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.bytes()).length)
                                message.ephemeralPublicKey = value;
                            else
                                delete message.ephemeralPublicKey;
                            continue;
                        }
                    case 8: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.bytes()).length)
                                message.pqCiphertext = value;
                            else
                                delete message.pqCiphertext;
                            continue;
                        }
                    case 9: {
                            if (wireType !== 0)
                                break;
                            if (value = reader.uint32())
                                message.signedPrekeyId = value;
                            else
                                delete message.signedPrekeyId;
                            continue;
                        }
                    case 10: {
                            if (wireType !== 0)
                                break;
                            message.oneTimePrekeyId = reader.uint32();
                            message._oneTimePrekeyId = "oneTimePrekeyId";
                            continue;
                        }
                    case 11: {
                            if (wireType !== 0)
                                break;
                            if (value = reader.uint32())
                                message.pqPrekeyId = value;
                            else
                                delete message.pqPrekeyId;
                            continue;
                        }
                    case 12: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.bytes()).length)
                                message.signature = value;
                            else
                                delete message.signature;
                            continue;
                        }
                    }
                    reader.skipType(wireType, _depth, tag);
                    if (!reader.discardUnknown) {
                        $util.makeProp(message, "$unknowns", false);
                        (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                    }
                }
                if (length !== $undefined) {
                    if (reader.pos !== end)
                        throw $RangeError("index out of range");
                    reader.len = length;
                }
                if (_end !== $undefined)
                    throw $Error("missing end group");
                return message;
            };

            /**
             * Decodes an EnvelopeProto message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {securemessaging.v1.EnvelopeProto & securemessaging.v1.EnvelopeProto.$Shape} EnvelopeProto
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            EnvelopeProto.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies an EnvelopeProto message.
             * @function verify
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            EnvelopeProto.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                let properties = {};
                if (message.type != null && $Object.hasOwnProperty.call(message, "type"))
                    if (typeof message.type !== "number" || (message.type | 0) !== message.type)
                        return "type: enum value expected";
                if (message.protocolVersion != null && $Object.hasOwnProperty.call(message, "protocolVersion"))
                    if (!$util.isInteger(message.protocolVersion))
                        return "protocolVersion: integer expected";
                if (message.sessionId != null && $Object.hasOwnProperty.call(message, "sessionId"))
                    if (!(message.sessionId && typeof message.sessionId.length === "number" || $util.isString(message.sessionId)))
                        return "sessionId: buffer expected";
                if (message.ratchetHeader != null && $Object.hasOwnProperty.call(message, "ratchetHeader")) {
                    let error = $root.securemessaging.v1.RatchetHeaderProto.verify(message.ratchetHeader, _depth + 1);
                    if (error)
                        return "ratchetHeader." + error;
                }
                if (message.ciphertext != null && $Object.hasOwnProperty.call(message, "ciphertext"))
                    if (!(message.ciphertext && typeof message.ciphertext.length === "number" || $util.isString(message.ciphertext)))
                        return "ciphertext: buffer expected";
                if (message.senderIdentityPublicKey != null && $Object.hasOwnProperty.call(message, "senderIdentityPublicKey"))
                    if (!(message.senderIdentityPublicKey && typeof message.senderIdentityPublicKey.length === "number" || $util.isString(message.senderIdentityPublicKey)))
                        return "senderIdentityPublicKey: buffer expected";
                if (message.ephemeralPublicKey != null && $Object.hasOwnProperty.call(message, "ephemeralPublicKey"))
                    if (!(message.ephemeralPublicKey && typeof message.ephemeralPublicKey.length === "number" || $util.isString(message.ephemeralPublicKey)))
                        return "ephemeralPublicKey: buffer expected";
                if (message.pqCiphertext != null && $Object.hasOwnProperty.call(message, "pqCiphertext"))
                    if (!(message.pqCiphertext && typeof message.pqCiphertext.length === "number" || $util.isString(message.pqCiphertext)))
                        return "pqCiphertext: buffer expected";
                if (message.signedPrekeyId != null && $Object.hasOwnProperty.call(message, "signedPrekeyId"))
                    if (!$util.isInteger(message.signedPrekeyId))
                        return "signedPrekeyId: integer expected";
                if (message.oneTimePrekeyId != null && $Object.hasOwnProperty.call(message, "oneTimePrekeyId")) {
                    properties._oneTimePrekeyId = 1;
                    if (!$util.isInteger(message.oneTimePrekeyId))
                        return "oneTimePrekeyId: integer expected";
                }
                if (message.pqPrekeyId != null && $Object.hasOwnProperty.call(message, "pqPrekeyId"))
                    if (!$util.isInteger(message.pqPrekeyId))
                        return "pqPrekeyId: integer expected";
                if (message.signature != null && $Object.hasOwnProperty.call(message, "signature"))
                    if (!(message.signature && typeof message.signature.length === "number" || $util.isString(message.signature)))
                        return "signature: buffer expected";
                return null;
            };

            /**
             * Creates an EnvelopeProto message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {securemessaging.v1.EnvelopeProto} EnvelopeProto
             */
            EnvelopeProto.fromObject = function (object, _depth) {
                if (object instanceof $root.securemessaging.v1.EnvelopeProto)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".securemessaging.v1.EnvelopeProto: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.securemessaging.v1.EnvelopeProto();
                if (object.type !== 0 && (typeof object.type !== "string" || $root.securemessaging.v1.EnvelopeType[object.type] !== 0))
                    switch (object.type) {
                    case "ENVELOPE_TYPE_UNSPECIFIED":
                    case 0:
                        message.type = 0;
                        break;
                    case "SESSION_INIT":
                    case 1:
                        message.type = 1;
                        break;
                    case "MESSAGE":
                    case 2:
                        message.type = 2;
                        break;
                    case "SESSION_RESET":
                    case 3:
                        message.type = 3;
                        break;
                    default:
                        if (typeof object.type === "number" && (object.type | 0) === object.type)
                            message.type = object.type;
                    }
                if (object.protocolVersion != null)
                    if ($Number(object.protocolVersion) !== 0)
                        message.protocolVersion = object.protocolVersion >>> 0;
                if (object.sessionId != null)
                    if (object.sessionId.length)
                        if (typeof object.sessionId === "string")
                            $util.base64.decode(object.sessionId, message.sessionId = $util.newBuffer($util.base64.length(object.sessionId)), 0);
                        else if (object.sessionId.length >= 0)
                            message.sessionId = object.sessionId;
                if (object.ratchetHeader != null) {
                    if (!$util.isObject(object.ratchetHeader))
                        throw $TypeError(".securemessaging.v1.EnvelopeProto.ratchetHeader: object expected");
                    message.ratchetHeader = $root.securemessaging.v1.RatchetHeaderProto.fromObject(object.ratchetHeader, _depth + 1);
                }
                if (object.ciphertext != null)
                    if (object.ciphertext.length)
                        if (typeof object.ciphertext === "string")
                            $util.base64.decode(object.ciphertext, message.ciphertext = $util.newBuffer($util.base64.length(object.ciphertext)), 0);
                        else if (object.ciphertext.length >= 0)
                            message.ciphertext = object.ciphertext;
                if (object.senderIdentityPublicKey != null)
                    if (object.senderIdentityPublicKey.length)
                        if (typeof object.senderIdentityPublicKey === "string")
                            $util.base64.decode(object.senderIdentityPublicKey, message.senderIdentityPublicKey = $util.newBuffer($util.base64.length(object.senderIdentityPublicKey)), 0);
                        else if (object.senderIdentityPublicKey.length >= 0)
                            message.senderIdentityPublicKey = object.senderIdentityPublicKey;
                if (object.ephemeralPublicKey != null)
                    if (object.ephemeralPublicKey.length)
                        if (typeof object.ephemeralPublicKey === "string")
                            $util.base64.decode(object.ephemeralPublicKey, message.ephemeralPublicKey = $util.newBuffer($util.base64.length(object.ephemeralPublicKey)), 0);
                        else if (object.ephemeralPublicKey.length >= 0)
                            message.ephemeralPublicKey = object.ephemeralPublicKey;
                if (object.pqCiphertext != null)
                    if (object.pqCiphertext.length)
                        if (typeof object.pqCiphertext === "string")
                            $util.base64.decode(object.pqCiphertext, message.pqCiphertext = $util.newBuffer($util.base64.length(object.pqCiphertext)), 0);
                        else if (object.pqCiphertext.length >= 0)
                            message.pqCiphertext = object.pqCiphertext;
                if (object.signedPrekeyId != null)
                    if ($Number(object.signedPrekeyId) !== 0)
                        message.signedPrekeyId = object.signedPrekeyId >>> 0;
                if (object.oneTimePrekeyId != null)
                    message.oneTimePrekeyId = object.oneTimePrekeyId >>> 0;
                if (object.pqPrekeyId != null)
                    if ($Number(object.pqPrekeyId) !== 0)
                        message.pqPrekeyId = object.pqPrekeyId >>> 0;
                if (object.signature != null)
                    if (object.signature.length)
                        if (typeof object.signature === "string")
                            $util.base64.decode(object.signature, message.signature = $util.newBuffer($util.base64.length(object.signature)), 0);
                        else if (object.signature.length >= 0)
                            message.signature = object.signature;
                return message;
            };

            /**
             * Creates a plain object from an EnvelopeProto message. Also converts values to other types if specified.
             * @function toObject
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {securemessaging.v1.EnvelopeProto} message EnvelopeProto
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            EnvelopeProto.toObject = function (message, options, _depth) {
                if (!options)
                    options = {};
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.type = options.enums === $String ? "ENVELOPE_TYPE_UNSPECIFIED" : 0;
                    object.protocolVersion = 0;
                    if (options.bytes === $String)
                        object.sessionId = "";
                    else {
                        object.sessionId = [];
                        if (options.bytes !== $Array)
                            object.sessionId = $util.newBuffer(object.sessionId);
                    }
                    object.ratchetHeader = null;
                    if (options.bytes === $String)
                        object.ciphertext = "";
                    else {
                        object.ciphertext = [];
                        if (options.bytes !== $Array)
                            object.ciphertext = $util.newBuffer(object.ciphertext);
                    }
                    if (options.bytes === $String)
                        object.senderIdentityPublicKey = "";
                    else {
                        object.senderIdentityPublicKey = [];
                        if (options.bytes !== $Array)
                            object.senderIdentityPublicKey = $util.newBuffer(object.senderIdentityPublicKey);
                    }
                    if (options.bytes === $String)
                        object.ephemeralPublicKey = "";
                    else {
                        object.ephemeralPublicKey = [];
                        if (options.bytes !== $Array)
                            object.ephemeralPublicKey = $util.newBuffer(object.ephemeralPublicKey);
                    }
                    if (options.bytes === $String)
                        object.pqCiphertext = "";
                    else {
                        object.pqCiphertext = [];
                        if (options.bytes !== $Array)
                            object.pqCiphertext = $util.newBuffer(object.pqCiphertext);
                    }
                    object.signedPrekeyId = 0;
                    object.pqPrekeyId = 0;
                    if (options.bytes === $String)
                        object.signature = "";
                    else {
                        object.signature = [];
                        if (options.bytes !== $Array)
                            object.signature = $util.newBuffer(object.signature);
                    }
                }
                if (message.type != null && $Object.hasOwnProperty.call(message, "type"))
                    object.type = options.enums === $String ? $root.securemessaging.v1.EnvelopeType[message.type] === $undefined ? message.type : $root.securemessaging.v1.EnvelopeType[message.type] : message.type;
                if (message.protocolVersion != null && $Object.hasOwnProperty.call(message, "protocolVersion"))
                    object.protocolVersion = message.protocolVersion;
                if (message.sessionId != null && $Object.hasOwnProperty.call(message, "sessionId"))
                    object.sessionId = options.bytes === $String ? $util.base64.encode(message.sessionId, 0, message.sessionId.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.sessionId) : message.sessionId;
                if (message.ratchetHeader != null && $Object.hasOwnProperty.call(message, "ratchetHeader"))
                    object.ratchetHeader = $root.securemessaging.v1.RatchetHeaderProto.toObject(message.ratchetHeader, options, _depth + 1);
                if (message.ciphertext != null && $Object.hasOwnProperty.call(message, "ciphertext"))
                    object.ciphertext = options.bytes === $String ? $util.base64.encode(message.ciphertext, 0, message.ciphertext.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.ciphertext) : message.ciphertext;
                if (message.senderIdentityPublicKey != null && $Object.hasOwnProperty.call(message, "senderIdentityPublicKey"))
                    object.senderIdentityPublicKey = options.bytes === $String ? $util.base64.encode(message.senderIdentityPublicKey, 0, message.senderIdentityPublicKey.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.senderIdentityPublicKey) : message.senderIdentityPublicKey;
                if (message.ephemeralPublicKey != null && $Object.hasOwnProperty.call(message, "ephemeralPublicKey"))
                    object.ephemeralPublicKey = options.bytes === $String ? $util.base64.encode(message.ephemeralPublicKey, 0, message.ephemeralPublicKey.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.ephemeralPublicKey) : message.ephemeralPublicKey;
                if (message.pqCiphertext != null && $Object.hasOwnProperty.call(message, "pqCiphertext"))
                    object.pqCiphertext = options.bytes === $String ? $util.base64.encode(message.pqCiphertext, 0, message.pqCiphertext.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.pqCiphertext) : message.pqCiphertext;
                if (message.signedPrekeyId != null && $Object.hasOwnProperty.call(message, "signedPrekeyId"))
                    object.signedPrekeyId = message.signedPrekeyId;
                if (message.oneTimePrekeyId != null && $Object.hasOwnProperty.call(message, "oneTimePrekeyId"))
                    object.oneTimePrekeyId = message.oneTimePrekeyId;
                if (message.pqPrekeyId != null && $Object.hasOwnProperty.call(message, "pqPrekeyId"))
                    object.pqPrekeyId = message.pqPrekeyId;
                if (message.signature != null && $Object.hasOwnProperty.call(message, "signature"))
                    object.signature = options.bytes === $String ? $util.base64.encode(message.signature, 0, message.signature.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.signature) : message.signature;
                return object;
            };

            /**
             * Converts this EnvelopeProto to JSON.
             * @function toJSON
             * @memberof securemessaging.v1.EnvelopeProto
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            EnvelopeProto.prototype.toJSON = function() {
                return EnvelopeProto.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for EnvelopeProto
             * @function getTypeUrl
             * @memberof securemessaging.v1.EnvelopeProto
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            EnvelopeProto.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/securemessaging.v1.EnvelopeProto";
            };

            return EnvelopeProto;
        })();

        return v1;
    })();

    return securemessaging;
})();

export {
  $root as default
};
