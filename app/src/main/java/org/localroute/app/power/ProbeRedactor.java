package org.localroute.app.power;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 电量取证页的记录脱敏：只保留判断接口形态需要的信息，不把凭据写进日志。
 *
 * <p>要判断的是「会话在 Cookie 还是 Authorization 头」「接口返回什么结构」，这两件事都不需要
 * 凭据的值本身——所以头只记名字，存储只记键名与长度，响应体里的凭据字段按名字打码。
 * 电量数值、房间号这类业务字段保留，否则看不出接口结构。
 *
 * <p>纯 Java，可在 JVM 用例里逐条断言。
 */
public final class ProbeRedactor {

    /** 响应体最多留这么多字符：菜单这类结构响应实测有 1.6 万字符，截短了会正好丢掉要找的入口。 */
    public static final int MAX_BODY = 20000;

    private static final Pattern SECRET_FIELD = Pattern.compile(
            "(\"(?:token|access_token|accessToken|refresh_token|refreshToken|authorization|"
                    + "password|passwd|pwd|ticket|sessionid|sessionId|jsessionid|cookie|"
                    + "real_name|nickname|phone|mobile|number|user_code|id_card|email|avatar)\"\\s*:\\s*\")"
                    + "([^\"]*)(\")",
            Pattern.CASE_INSENSITIVE);

    /** URL 查询串里的凭据：短链常把 token 明文挂在地址上。 */
    private static final Pattern SECRET_QUERY = Pattern.compile(
            "([?&](?:token|access_token|authorization|ticket|password|sign)=)([^&#\\s]*)",
            Pattern.CASE_INSENSITIVE);

    /**
     * 转接令牌还会被 URL 编码后嵌进别人的 redirect_uri 里（微信授权链就是这样），
     * 只按 {@code ?token=} 匹配会漏掉，所以这里对已知名字同时认原样与百分号编码两种写法。
     */
    private static final Pattern NESTED_TOKEN = Pattern.compile(
            "(saas_wap_token(?:=|%3D))((?:(?!&|%26|[\\s\"]).)*)",
            Pattern.CASE_INSENSITIVE);

    private ProbeRedactor() {
    }

    /** 响应体：凭据字段打码后截断。 */
    @NonNull
    public static String body(@Nullable String raw) {
        if (raw == null || raw.isEmpty()) {
            return "(空)";
        }
        Matcher matcher = SECRET_FIELD.matcher(raw);
        // StringBuilder 重载要 API 34，minSdk 29 只能用 StringBuffer 那套。
        StringBuffer out = new StringBuffer();
        while (matcher.find()) {
            String replacement = matcher.group(1) + "<已打码 " + matcher.group(2).length() + " 字符>"
                    + matcher.group(3);
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        String text = out.toString();
        return text.length() <= MAX_BODY ? text
                : text.substring(0, MAX_BODY) + "…(共 " + text.length() + " 字符)";
    }

    /** 请求头：只记名字，值一律不记。 */
    @NonNull
    public static String headerNames(@Nullable String commaSeparated) {
        if (commaSeparated == null || commaSeparated.trim().isEmpty()) {
            return "(无自定义头)";
        }
        StringBuilder out = new StringBuilder();
        for (String name : commaSeparated.split(",")) {
            String trimmed = name.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (out.length() > 0) {
                out.append(',');
            }
            out.append(trimmed);
        }
        return out.length() == 0 ? "(无自定义头)" : out.toString();
    }

    /** Cookie 串：只记名字，值一律不记。 */
    @NonNull
    public static String cookieNames(@Nullable String cookieHeader) {
        if (cookieHeader == null || cookieHeader.trim().isEmpty()) {
            return "(无 Cookie)";
        }
        StringBuilder out = new StringBuilder();
        for (String pair : cookieHeader.split(";")) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if (name.isEmpty()) {
                continue;
            }
            if (out.length() > 0) {
                out.append(',');
            }
            out.append(name);
        }
        return out.length() == 0 ? "(无 Cookie)" : out.toString();
    }

    /** 一行接口记录。 */
    @NonNull
    public static String request(@Nullable String method, @Nullable String url, int status,
                                 @Nullable String headerNames, @Nullable String rawBody) {
        return String.format(Locale.US, "%s %s → %d | 头[%s] | 体 %s",
                method == null ? "?" : method, url(url), status,
                headerNames(headerNames), body(rawBody));
    }

    /** 地址：查询串里的凭据打码，路径与其余参数保留（要靠它们认接口）。 */
    @NonNull
    public static String url(@Nullable String raw) {
        if (raw == null || raw.isEmpty()) {
            return "?";
        }
        Matcher matcher = SECRET_QUERY.matcher(raw);
        StringBuffer out = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(out, Matcher.quoteReplacement(
                    matcher.group(1) + "<已打码 " + matcher.group(2).length() + " 字符>"));
        }
        matcher.appendTail(out);
        Matcher nested = NESTED_TOKEN.matcher(out.toString());
        StringBuffer second = new StringBuffer();
        while (nested.find()) {
            nested.appendReplacement(second, Matcher.quoteReplacement(
                    nested.group(1) + "<已打码 " + nested.group(2).length() + " 字符>"));
        }
        nested.appendTail(second);
        return second.toString();
    }
}