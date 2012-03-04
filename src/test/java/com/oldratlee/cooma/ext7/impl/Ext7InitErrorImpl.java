/*
 * Copyright 1999-2011 Alibaba Group.
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.oldratlee.cooma.ext7.impl;

import com.oldratlee.cooma.Configs;
import com.oldratlee.cooma.ext7.Ext7;

/**
 * @author oldratlee
 */
public class Ext7InitErrorImpl implements Ext7 {
    
    static {
        if(true) {
            throw new RuntimeException("intended!");
        }
    }

    public String echo(Configs config, String s) {
        return "";
    }

}