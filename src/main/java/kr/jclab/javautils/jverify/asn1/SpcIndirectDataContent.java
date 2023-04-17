/**
 * Copyright 2012 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kr.jclab.javautils.jverify.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.DigestInfo;

import java.io.IOException;

/**
 * <pre>
 * SpcIndirectDataContent ::= SEQUENCE {
 *     data                    SpcAttributeTypeAndOptionalValue,
 *     messageDigest           DigestInfo
 * }
 * </pre>
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcIndirectDataContent extends ASN1Object {

    private final SpcAttributeTypeAndOptionalValue data;
    private final DigestInfo messageDigest;

    public static SpcIndirectDataContent getInstance(Object contentInfo) throws IOException {
        if (contentInfo instanceof ASN1Sequence) {
            ASN1Sequence contentInfoSeq = (ASN1Sequence) contentInfo;
            SpcAttributeTypeAndOptionalValue data = SpcAttributeTypeAndOptionalValue.getInstance(contentInfoSeq.getObjectAt(0));
            DigestInfo messageDigest = DigestInfo.getInstance(contentInfoSeq.getObjectAt(1).toASN1Primitive().getEncoded());
            return new SpcIndirectDataContent(data, messageDigest);
        }
        return getInstance(ASN1Sequence.getInstance(contentInfo));
    }

    public SpcIndirectDataContent(SpcAttributeTypeAndOptionalValue data, DigestInfo messageDigest) {
        this.data = data;
        this.messageDigest = messageDigest;
    }

    public SpcAttributeTypeAndOptionalValue getData() {
        return data;
    }

    public DigestInfo getMessageDigest() {
        return messageDigest;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(data);
        v.add(messageDigest);
        
        return new BERSequence(v);
    }
}
