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

import com.alibaba.cooma.internal.utils.Holder;
import com.alibaba.cooma.internal.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

/**
 * 加载和管理扩展。
 * <p/>
 * <ul>
 * <li>管理的扩展实例是<b>单例</b>。
 * <li>Wrapper实例每次获得扩展实例重新创建，并Wrap到扩展实例上。
 * </ul>
 *
 * @author Jerry Lee(oldratlee AT gmail DOT com)
 * @see Extension
 * @see <a href="http://java.sun.com/j2se/1.5.0/docs/guide/jar/jar.html#Service%20Provider">Service implementation of JDK5</a>
 * @since 0.1.0
 */
public class ExtensionLoader<T> {

    private static final Logger logger = LoggerFactory.getLogger(ExtensionLoader.class);

    private static final String EXTENSION_CONF_DIRECTORY = "META-INF/extensions/";

    private static final String PREFIX_ADAPTIVE_CLASS = "*";
    private static final String PREFIX_WRAPPER_CLASS = "+";

    private static final Pattern NAME_SEPARATOR = Pattern.compile("\\s*,+\\s*"); // 以逗号（忽略连续的逗号，逗号前后可以包含空格）分隔
    private static final Pattern NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_]+");

    private static final ConcurrentMap<Class<?>, ExtensionLoader<?>> EXTENSION_LOADERS = new ConcurrentHashMap<Class<?>, ExtensionLoader<?>>();

    /**
     * {@link ExtensionLoader} 的工厂方法。
     *
     * @param type 扩展点接口类型
     * @param <T> 扩展点类型
     * @return {@link ExtensionLoader}实例
     * @throws IllegalArgumentException 参数为<code>null</code>；
     *                                  或是扩展点接口上没有{@link Extension}注解。
     * @since 0.1.0
     */
    @SuppressWarnings("unchecked")
    public static <T> ExtensionLoader<T> getExtensionLoader(Class<T> type) {
        if (type == null) {
            throw new IllegalArgumentException("Extension type == null");
        }
        // 不是接口
        if (!type.isInterface()) {
            throw new IllegalArgumentException("Extension type(" + type.getName() + ") is not interface!");
        }

        // type 没有 @Extension 注解
        if (!withExtensionAnnotation(type)) {
            throw new IllegalArgumentException(
                    "type(" + type.getName() + ") is not a extension, because WITHOUT @Extension Annotation!");
        }

        ExtensionLoader<T> loader = (ExtensionLoader<T>) EXTENSION_LOADERS.get(type);
        if (loader == null) {
            // 如果不存在的话创建一个
            EXTENSION_LOADERS.putIfAbsent(type, new ExtensionLoader<T>(type));
            loader = (ExtensionLoader<T>) EXTENSION_LOADERS.get(type);
        }
        return loader;
    }

    public T getExtension(String name) {
        if (StringUtils.isEmpty(name)) {
            throw new IllegalArgumentException("Extension name == null");
        }
        return this.getExtension(name, new HashMap<String, String>(), new ArrayList<String>());
    }

    public T getExtension(String name, Map<String, String> properties) {
        if (StringUtils.isEmpty(name)) {
            throw new IllegalArgumentException("Extension name == null");
        }
        return this.getExtension(name, properties, new ArrayList<String>());
    }

    public T getExtension(Map<String, String> properties) {
        String name = properties.get(type.getName()); // FIXME 使用类名作为Key，这里Hard Code了逻辑！
        if (StringUtils.isEmpty(name)) {
            // 如果没有在配置文件中配置的话，则尝试获取注解上的默认配置
            name = defaultExtension;
        }
        return this.getExtension(name, properties, new ArrayList<String>());
    }

    public T getExtension(String name, List<String> wrappers) {
        if (wrappers == null) {
            throw new IllegalArgumentException("wrappers == null");
        }
        return this.getExtension(name, new HashMap<String, String>(), wrappers);
    }

    public T getExtension(String name, Map<String, String> properties, List<String> wrappers) {
        if (StringUtils.isEmpty(name)) {
            throw new IllegalArgumentException("Extension name == null");
        }
        T extension = this.createExtension(name, properties);
        this.inject(extension, properties);
        return this.createWrapper(extension, properties, wrappers);
    }

    /**
     * 返回注解中配置的缺省的扩展。
     *
     * @throws IllegalStateException 指定的扩展没有设置缺省扩展点
     * @since 0.1.0
     */
    public T getDefaultExtension() {
        if (null == defaultExtension || defaultExtension.length() == 0) {
            throw new IllegalStateException("No default extension on extension " + type.getName());
        }
        return this.getExtension(defaultExtension);
    }

    /**
     * 返回缺省的扩展。
     *
     * @param wrappers 返回的实例上，要启用的Wrapper。
     * @throws IllegalStateException 指定的扩展没有设置缺省扩展点
     * @since 0.2.1
     */
    public T getDefaultExtension(List<String> wrappers) {
        if (null == defaultExtension || defaultExtension.length() == 0) {
            throw new IllegalStateException("No default extension on extension " + type.getName());
        }
        return this.getExtension(defaultExtension, wrappers);
    }

    /**
     * 检查是否有指定名字的扩展。
     *
     * @param name 扩展名
     * @return 有指定名字的扩展，则<code>true</code>，否则<code>false</code>。
     * @throws IllegalArgumentException 参数为<code>null</code>或是空字符串。
     * @since 0.1.0
     */
    public boolean hasExtension(String name) {
        if (name == null || name.length() == 0) {
            throw new IllegalArgumentException("Extension name == null");
        }
        return this.getExtensionClasses().get(name) != null;
    }

    /**
     * 检查是否有指定缺省的扩展。
     *
     * @return 有指定缺省的扩展，则<code>true</code>，否则<code>false</code>。
     * @since 0.1.0
     */
    public boolean hasDefaultExtension() {
        return !(null == defaultExtension || defaultExtension.length() == 0);

    }

    /**
     * 获取扩展点实现的所有扩展点名。
     *
     * @since 0.1.0
     */
    public Set<String> getSupportedExtensions() {
        Map<String, Class<?>> classes = this.getExtensionClasses();
        return Collections.unmodifiableSet(new HashSet<String>(classes.keySet()));
    }

    /**
     * 返回缺省的扩展点名，如果没有设置缺省则返回<code>null</code>。
     *
     * @since 0.1.0
     */
    public String getDefaultExtensionName() {
        return defaultExtension;
    }

    public Map<String, Map<String, String>> getExtensionAttribute() {
        // 先一下加载扩展点类
        this.getExtensionClasses();
        return name2Attributes;
    }

    public Map<String, String> getExtensionAttribute(String name) {
        if (name == null || name.length() == 0) {
            throw new IllegalArgumentException("Extension name == null");
        }

        // 先一下加载扩展点类，如果没有这个名字的扩展点类，会抛异常，
        // 这样不用创建不必要的Holder。
        getExtensionClass(name);

        return name2Attributes.get(name);
    }

    @Override
    public String toString() {
        return this.getClass().getName() + "<" + type.getName() + ">";
    }

    // ==============================
    // internal methods
    // ==============================

    private final Class<T> type;

    // 记录在注解上的默认配置
    private final String defaultExtension;

    private ExtensionLoader(Class<T> type) {
        this.type = type;

        String defaultExt = null;
        final Extension annotation = type.getAnnotation(Extension.class);
        if (annotation != null) {
            String value = annotation.value();
            if (value != null && (value = value.trim()).length() > 0) {
                String[] names = NAME_SEPARATOR.split(value);
                if (names.length > 1) {
                    // 只能默认指定一个
                    throw new IllegalStateException("more than 1 default extension name on extension " + type.getName() + ": " + Arrays.toString(names));
                }
                if (names.length == 1 && names[0].trim().length() > 0) {
                    defaultExt = names[0].trim();
                }
                if (!isValidExtName(defaultExt)) {
                    throw new IllegalStateException("default name(" + defaultExt + ") of extension " + type.getName() + " is invalid!");
                }
            }
        }
        defaultExtension = defaultExt;
    }

    @SuppressWarnings("unchecked")
    private T createExtension(String name, Map<String, String> properties) {
        Class<?> clazz = this.getExtensionClass(name);
        try {
            return this.inject((T) clazz.newInstance(), properties);
        } catch (Throwable t) {
            String msg = "Fail to create extension " + name +
                    " of extension point " + type.getName() + ", cause: " + t.getMessage();
            logger.warn(msg);
            throw new IllegalStateException(msg, t);
        }
    }

    private T createWrapper(T instance, Map<String, String> properties, List<String> wrappers) {
        if (wrappers != null) {
            // 遍历调用 wrapper 对实例逐层包装
            for (String name : wrappers) {
                try {
                    instance = this.inject(name2Wrapper.get(name).getConstructor(type).newInstance(instance), properties);
                } catch (Throwable e) {
                    throw new IllegalStateException("Fail to create wrapper(" + name + ") for extension point " + type);
                }
            }
        }

        return instance;
    }

    /**
     * 遍历调用实例的 setter 方法（入参必须是被 @Extension 注解的接口类型）
     *
     * @param instance
     * @param properties
     * @return
     */
    private T inject(T instance, Map<String, String> properties) {
        for (Method method : instance.getClass().getMethods()) {
            if (method.getName().startsWith("set")
                    && method.getParameterTypes().length == 1
                    && Modifier.isPublic(method.getModifiers())) {

                // 获取参数类型
                Class<?> pt = method.getParameterTypes()[0];
                // 参数是接口类型，且被 @Extension 注解
                if (pt.isInterface() && withExtensionAnnotation(pt)) {
                    // 防止循环引用
                    if (pt.equals(type)) { // avoid obvious dead loop TODO avoid complex nested loop setting?
                        logger.warn("Ignore self set(" + method + ") for class(" + instance.getClass() + ") when inject.");
                        continue;
                    }
                    try {
                        // 获取参数类型对应的实现
                        Object prototype = getExtensionLoader(pt).getExtension(properties);
                        // 调用 setter
                        method.invoke(instance, prototype);
                        // FIXME 要注入属性到Extension和Wrapper！
                    } catch (Throwable t) {
                        String errMsg = "Fail to inject via method " + method.getName()
                                + " of interface to extension implementation " + instance.getClass() +
                                " for extension point " + type.getName() + ", cause: " + t.getMessage();
                        logger.warn(errMsg, t);
                        throw new IllegalStateException(errMsg, t);
                    }
                }
            }
        }
        return instance;
    }

    // ====================================
    // get & load Extension Class
    // ====================================

    // Holder<Map<ext-name, ext-class>>
    // Map 对应的 key 是属性项 name，value 是对应实现类的 class 对象
    private final Holder<Map<String, Class<?>>> extClassesHolder = new Holder<Map<String, Class<?>>>();

    // Map 对应的 key 是属性项 name，value 是对应属性的解析得到的 map 对象
    private volatile Map<String, Map<String, String>> name2Attributes;

    // 记录实现类 class 对象与 name 的反向映射
    private final ConcurrentMap<Class<?>, String> extClass2Name = new ConcurrentHashMap<Class<?>, String>();

    private volatile Class<?> adaptiveClass = null;

    // Map 对应的 key 是属性项 name，value 是对应实现类 Wrapper 的 class 对象
    private volatile Map<String, Class<? extends T>> name2Wrapper;

    private final Map<String, IllegalStateException> extClassLoadExceptions = new ConcurrentHashMap<String, IllegalStateException>();

    /**
     * 获取指定 name 对应实现类的 class 对象
     *
     * @param name
     * @return
     */
    private Class<?> getExtensionClass(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Extension name == null");
        }

        Class<?> clazz = this.getExtensionClasses().get(name);
        if (clazz == null) {
            throw this.findExtensionClassLoadException(name);
        }
        return clazz;
    }

    /**
     * Thread-safe.
     */
    private Map<String, Class<?>> getExtensionClasses() {
        // 从缓存中获取
        Map<String, Class<?>> classes = extClassesHolder.get();
        if (classes == null) {
            synchronized (extClassesHolder) {
                classes = extClassesHolder.get();
                if (classes == null) { // double check
                    this.loadExtensionClasses0();
                    classes = extClassesHolder.get();
                }
            }
        }
        return classes;
    }

    private IllegalStateException findExtensionClassLoadException(String name) {
        String msg = "No such extension " + type.getName() + " by name " + name;

        for (Map.Entry<String, IllegalStateException> entry : extClassLoadExceptions.entrySet()) {
            if (entry.getKey().toLowerCase().contains(name.toLowerCase())) {
                IllegalStateException e = entry.getValue();
                return new IllegalStateException(msg + ", cause: " + e.getMessage(), e);
            }
        }

        StringBuilder buf = new StringBuilder(msg);
        if (!extClassLoadExceptions.isEmpty()) {
            buf.append(", possible causes: ");
            int i = 1;
            for (Map.Entry<String, IllegalStateException> entry : extClassLoadExceptions.entrySet()) {
                buf.append("\r\n(");
                buf.append(i++);
                buf.append(") ");
                buf.append(entry.getKey());
                buf.append(":\r\n");
                buf.append(StringUtils.toString(entry.getValue()));
            }
        }
        return new IllegalStateException(buf.toString());
    }

    private void loadExtensionClasses0() {
        Map<String, Class<?>> extName2Class = new HashMap<String, Class<?>>();
        Map<String, Class<? extends T>> tmpName2Wrapper = new LinkedHashMap<String, Class<? extends T>>();
        Map<String, Map<String, String>> tmpName2Attributes = new LinkedHashMap<String, Map<String, String>>();
        String fileName = null;
        try {
            // 获取类加载器
            ClassLoader classLoader = getClassLoader();
            fileName = EXTENSION_CONF_DIRECTORY + type.getName(); // "META-INF/extensions/" + 类全限定名
            Enumeration<java.net.URL> urls;
            if (classLoader != null) {
                urls = classLoader.getResources(fileName);
            } else {
                urls = ClassLoader.getSystemResources(fileName);
            }

            if (urls != null) { // 找到的urls为null，或是没有找到文件，即认为是没有找到扩展点
                while (urls.hasMoreElements()) {
                    java.net.URL url = urls.nextElement();
                    // 逐个解析 SPI 配置文件
                    this.readExtension0(extName2Class, tmpName2Attributes, tmpName2Wrapper, classLoader, url);
                }
            }
        } catch (Throwable t) {
            logger.error("Exception when load extension point(interface: " +
                    type.getName() + ", description file: " + fileName + ").", t);
        }

        extClassesHolder.set(extName2Class);
        name2Attributes = tmpName2Attributes;
        name2Wrapper = tmpName2Wrapper;
    }

    /**
     * @param extName2Class name 以及对应的实现类 class 对象
     * @param name2Attributes name 以及对应的 attribute 列表
     * @param name2Wrapper name 以及对应的 Wrapper 实现类 class 对象
     * @param classLoader
     * @param url
     */
    private void readExtension0(
            Map<String, Class<?>> extName2Class, Map<String, Map<String, String>> name2Attributes,
            Map<String, Class<? extends T>> name2Wrapper, ClassLoader classLoader, URL url) {

        // 加载 SPI 配置文件
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(url.openStream(), "utf-8"));
            String line;
            while ((line = reader.readLine()) != null) {
                String config = line;

                /**
                 * 包含 “#”，说明包含注释，如果 “#” 之前不存在任何字符，说明是纯注释，跳过
                 */
                final int ci = config.indexOf('#');
                if (ci >= 0) config = config.substring(0, ci);
                config = config.trim();
                if (config.length() == 0) continue; // 跳过纯注释

                // eg. racing=com.alibaba.demo.cooma.car.impl.RacingCar
                try {
                    // name为属性key，body为属性value，attribute为括号中参数列表
                    String name = null, body = null, attribute = null;
                    int i = config.indexOf('=');
                    if (i > 0) {
                        name = config.substring(0, i).trim();
                        body = config.substring(i + 1).trim();
                    }
                    // 没有配置文件中没有扩展点名，从实现类的Extension注解上读取。
                    if (name == null || name.length() == 0) {
                        // 没有配置 key
                        throw new IllegalStateException("missing extension name, config value: " + config);
                    }
                    int j = config.indexOf("(", i);
                    if (j > 0) {
                        if (config.charAt(config.length() - 1) != ')') {
                            // 括号不匹配
                            throw new IllegalStateException("missing ')' of extension attribute!");
                        }
                        body = config.substring(i + 1, j).trim();
                        attribute = config.substring(j + 1, config.length() - 1);
                    }

                    Class<? extends T> clazz = Class.forName(body, true, classLoader).asSubclass(type);
                    // 当前类不是接口的实现类
                    if (!type.isAssignableFrom(clazz)) {
                        throw new IllegalStateException("Error when load extension class(interface: " +
                                type.getName() + ", class line: " + clazz.getName() + "), class "
                                + clazz.getName() + "is not subtype of interface.");
                    }

                    if (name.startsWith(PREFIX_ADAPTIVE_CLASS)) { // "*" 开头
                        if (adaptiveClass == null) {
                            adaptiveClass = clazz;
                        } else if (!adaptiveClass.equals(clazz)) {
                            // 存在多个适配的实现类
                            throw new IllegalStateException("More than 1 adaptive class found: "
                                    + adaptiveClass.getClass().getName() + ", " + clazz.getClass().getName());
                        }
                    } else { // 不是以 "*" 开头
                        // 如果是以 “+” 开头说明是 Wrapper 类
                        final boolean isWrapper = name.startsWith(PREFIX_WRAPPER_CLASS);
                        if (isWrapper) {
                            // 去掉 “+”
                            name = name.substring(PREFIX_WRAPPER_CLASS.length());
                        }

                        String[] nameList = NAME_SEPARATOR.split(name);
                        for (String n : nameList) {
                            if (!isValidExtName(n)) {
                                // 不是合法的类限定名称
                                throw new IllegalStateException("name(" + n + ") of extension " + type.getName() + "is invalid!");
                            }

                            if (isWrapper) { // 是包装类
                                try {
                                    clazz.getConstructor(type); // 检测是否包含 SPI 接口类型的构造函数
                                    name2Wrapper.put(name, clazz);
                                } catch (NoSuchMethodException e) {
                                    throw new IllegalStateException("wrapper class(" + clazz + ") has NO copy constructor!", e);
                                }
                            } else { // 不是包装类
                                try {
                                    clazz.getConstructor(); // 检测是否包含默认构造函数
                                } catch (NoSuchMethodException e) {
                                    throw new IllegalStateException("extension class(" + clazz + ") has NO default constructor!", e);
                                }
                                if (extName2Class.containsKey(n)) {
                                    // 存在重复配置
                                    if (extName2Class.get(n) != clazz) {
                                        throw new IllegalStateException("Duplicate extension " +
                                                type.getName() + " name " + n +
                                                " on " + clazz.getName() + " and " + clazz.getName());
                                    }
                                } else {
                                    extName2Class.put(n, clazz);
                                }
                                // parseExtAttribute 负责将字符串属性配置转换成 map 类型
                                name2Attributes.put(n, parseExtAttribute(attribute));

                                if (!extClass2Name.containsKey(clazz)) {
                                    extClass2Name.put(clazz, n); // 实现类到扩展点名的Map中，记录了一个就可以了
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    IllegalStateException e = new IllegalStateException("Failed to load config line(" + line +
                            ") of config file(" + url + ") for extension(" + type.getName() +
                            "), cause: " + t.getMessage(), t);
                    logger.warn("", e);
                    extClassLoadExceptions.put(line, e);
                }
            } // end of while read lines
        } catch (Throwable t) {
            logger.error("Exception when load extension class(interface: " +
                    type.getName() + ", class file: " + url + ") in " + url, t);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Throwable t) {
                    // ignore
                }
            }
        }
    }

    // =========================
    // small helper methods
    // =========================

    private static ClassLoader getClassLoader() {
        // 获取当前线程的类加载器
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader != null) {
            return classLoader;
        }
        // 获取 ExtensionLoader 类的类加载器
        classLoader = ExtensionLoader.class.getClassLoader();
        if (classLoader != null) {
            return classLoader;
        }
        return classLoader;
    }

    private static <T> boolean withExtensionAnnotation(Class<T> type) {
        return type.isAnnotationPresent(Extension.class);
    }

    private static boolean isValidExtName(String name) {
        return NAME_PATTERN.matcher(name).matches();
    }

    /**
     * <code>
     * "attrib1=value1,attrib2=value2,isProvider,order=3" =>
     * {"attrib1"="value1", "attrib2"="value2", "isProvider"="", "order"="3"}
     * </code>
     */
    static Map<String, String> parseExtAttribute(String attribute) {
        Map<String, String> ret = new HashMap<String, String>();
        if (attribute == null || attribute.length() == 0) return ret;

        String[] parts = attribute.split(",");
        for (String part : parts) {
            part = part.trim();
            int idx = part.indexOf('=');
            if (idx > 0) {
                ret.put(part.substring(0, idx).trim(), part.substring(idx + 1).trim());
            } else {
                ret.put(part, "");
            }
        }

        return ret;
    }
}
