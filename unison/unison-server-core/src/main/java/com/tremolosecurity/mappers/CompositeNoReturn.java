/*
 * Copyright 2025 Tremolo Security, Inc.
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

package com.tremolosecurity.mappers;

import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.CustomMapping;
import com.tremolosecurity.saml.Attribute;

import java.io.Serializable;
import java.util.ArrayList;

public class CompositeNoReturn implements CustomMapping {
    String pattern;
    ArrayList<MappingPart> composite;

    @Override
    public Attribute doMapping(User user, String name) {
        boolean foundAtLeastOneAttribute = false;
        Attribute attribute = new Attribute(name);

        StringBuffer b = new StringBuffer();
        for (MappingPart mp : composite) {
            if (mp.isAttr) {
                if (user.getAttribs().containsKey(mp.val)) {
                    foundAtLeastOneAttribute = true;
                    b.append(user.getAttribs().get(mp.val).getValues().get(0));
                }
            } else {
                b.append(mp.val);
            }
        }

        attribute.getValues().add(b.toString());

        if (foundAtLeastOneAttribute) {
            return attribute;
        } else {
            return null;
        }
    }

    @Override
    public void setParams(String... params) {
        String b64 = params[0];
        pattern = new String(java.util.Base64.getDecoder().decode(b64));

        composite = new ArrayList<MappingPart>();
        int lastIndex = 0;
        int index = pattern.indexOf('$');
        while (index >= 0) {
            MappingPart mp = new MappingPart();
            mp.isAttr = false;
            mp.val = pattern.substring(lastIndex,index);
            composite.add(mp);

            lastIndex = pattern.indexOf('}',index) + 1;
            String reqName = pattern.substring(index + 2,lastIndex - 1);
            mp = new MappingPart();
            mp.isAttr = true;
            mp.val = reqName;
            composite.add(mp);

            index = pattern.indexOf('$',index+1);
        }
        MappingPart mp = new MappingPart();
        mp.isAttr = false;
        mp.val = pattern.substring(lastIndex);
        composite.add(mp);
    }
}

class MappingPart implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -8283736662740071079L;
    boolean isAttr;
    String val;
}