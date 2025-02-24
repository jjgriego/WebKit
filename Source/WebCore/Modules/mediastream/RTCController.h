/*
 * Copyright (C) 2017 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include "SecurityOrigin.h"
#include <wtf/Vector.h>
#include <wtf/WeakHashSet.h>

namespace WebCore {

class Document;
class RTCPeerConnection;
class WeakPtrImplWithEventTargetData;

class RTCController {
public:
    RTCController() = default;

#if ENABLE(WEB_RTC)
    ~RTCController();

    void reset(bool shouldFilterICECandidates);

    void add(RTCPeerConnection&);
    void remove(RTCPeerConnection&);

    WEBCORE_EXPORT void disableICECandidateFilteringForAllOrigins();
    WEBCORE_EXPORT void disableICECandidateFilteringForDocument(Document&);
    WEBCORE_EXPORT void enableICECandidateFiltering();

private:

    bool shouldDisableICECandidateFiltering(Document&);

    struct PeerConnectionOrigin {
        Ref<SecurityOrigin> topOrigin;
        Ref<SecurityOrigin> clientOrigin;
    };
    Vector<PeerConnectionOrigin> m_filteringDisabledOrigins;
    WeakHashSet<RTCPeerConnection, WeakPtrImplWithEventTargetData> m_peerConnections;
    bool m_shouldFilterICECandidates { true };
#endif
};

} // namespace WebCore
