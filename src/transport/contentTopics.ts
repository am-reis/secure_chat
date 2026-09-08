/**
 * Phase 21: "Do not use /user/<public-key> as a content topic. Content
 * topics can be visible to infrastructure participants. Use an
 * application-level topic such as /myapp/1/message/proto... Keep
 * recipient/session identity inside the encrypted application envelope
 * whenever possible."
 *
 * A single shared topic per envelope type is used for ALL sessions and ALL
 * users of this application — recipient routing happens entirely inside
 * the encrypted envelope (the sessionId field), never in the topic string.
 * This trades off some efficiency (every client technically receives every
 * other client's envelopes on this topic and discards the ones not
 * addressed to a session it knows about) for exactly the metadata-privacy
 * property Phase 21 asks for: an observer of the pubsub topic learns
 * nothing about who is messaging whom, only that *some* SESSION_INIT or
 * MESSAGE traffic occurred. Real deployments may want sharded/rotating
 * topics for scale, which is a separate concern from this privacy property
 * and can be layered on later without changing anything above this module.
 *
 * NOTE: real Waku also has pubsub-topic-level sharding (which network
 * shard a node is on) — out of scope here; this module only covers content
 * topics, which is what Phase 21 itself scopes to.
 */
import { CURRENT_PROTOCOL_VERSION } from "../prekeys/PreKeyBundle.js";

const APP_NAME = "secure-messaging";

export function sessionInitContentTopic(protocolVersion: number = CURRENT_PROTOCOL_VERSION): string {
    return `/${APP_NAME}/${protocolVersion}/session-init/proto`;
}

export function messageContentTopic(protocolVersion: number = CURRENT_PROTOCOL_VERSION): string {
    return `/${APP_NAME}/${protocolVersion}/message/proto`;
}

export function sessionResetContentTopic(protocolVersion: number = CURRENT_PROTOCOL_VERSION): string {
    return `/${APP_NAME}/${protocolVersion}/session-reset/proto`;
}
