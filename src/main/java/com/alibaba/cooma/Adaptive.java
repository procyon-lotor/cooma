/*
 * Copyright 2012-2013 Cooma Team.
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

package com.alibaba.cooma;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 提供信息用于{@link ExtensionLoader}生成自适应实例（Adaptive Instance）。
 *
 * @author Jerry Lee(oldratlee AT gmail DOT com)
 * @see ExtensionLoader
 * @see Config
 * @see Extension
 * @since 0.1.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface Adaptive {

    /**
     * {@link Config}的Key列表，这些Key在{@link Config}中对应的Value是自适应实例方法调用时真正执行调用的扩展的名称。
     * <br/>
     * 如果这些Key在{@link Config}中都没有Value，自适应实例会使用缺省扩展（在扩展点接口的{@link Extension}上设置的）。
     * <p/>
     * eg. <code>String[] {"key1", "key2"}</code>表示：
     * <ol>
     * <li>使用<code>key1</code>的值作为自适应实例真正调用的扩展实现的名称。
     * <li>如果<code>key1</code>没有对应的值，则使用<code>key2</code>的值作为自适应实例真正调用的扩展实现的名称。
     * <li>如果<code>key2</code>没有对应的值，则使用缺省扩展。
     * <li>如果没有缺省扩展，则在获取自适应实例时，会抛出{@link IllegalStateException}。
     * </ol>
     * <p/>
     * 缺省是扩展点接口名的点分小写形式。
     * eg. 扩展点接口名<code>com.alibaba.cooma.FooBizService</code>, 缺省key是<code>String[] {"foo.biz.service"}</code>。
     *
     * @see Extension#value()
     * @since 0.1.0
     */
    String[] value() default {};
}