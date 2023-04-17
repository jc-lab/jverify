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
 * SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
 *     type                    OBJECT IDENTIFIER,
 *     value                   ANY DEFINED BY type OPTIONAL
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcAttributeTypeAndOptionalValue extends ASN1Object {

    private final ASN1ObjectIdentifier type;
    private final ASN1Object value;

    public static SpcAttributeTypeAndOptionalValue getInstance(Object input) throws IOException {
        if (input instanceof ASN1Sequence) {
            ASN1Sequence sequence = (ASN1Sequence) input;
            ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
            ASN1Object value = (ASN1Object) sequence.getObjectAt(1);
            return new SpcAttributeTypeAndOptionalValue(type, value);
        }
        return getInstance(ASN1Sequence.getInstance(input));
    }

    public SpcAttributeTypeAndOptionalValue(ASN1ObjectIdentifier type, ASN1Object value) {
        this.type = type;
        this.value = value;
    }

    public ASN1ObjectIdentifier getType() {
        return type;
    }

    public ASN1Object getValue() {
        return value;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(type);
        if (value != null) {
            v.add(value);
        }
        
        return new BERSequence(v);
    }
}
