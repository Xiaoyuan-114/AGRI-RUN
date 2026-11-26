package org.localroute.app.power;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** 取证记录脱敏：凭据只留名字与长度，业务字段保留。 */
public class ProbeRedactorTest {

    @Test public void masksCredentialFieldsButKeepsBusinessValues() {
        String raw = "{\"token\":\"abc123secret\",\"data\":{\"room\":\"A-301\",\"remain\":196.33}}";
        String out = ProbeRedactor.body(raw);

        assertFalse(out.contains("abc123secret"));
        assertTrue(out.contains("<已打码 12 字符>"));
        assertTrue(out.contains("\"remain\":196.33"));
        assertTrue(out.contains("A-301"));
    }

    @Test public void masksRegardlessOfFieldCase() {
        String out = ProbeRedactor.body("{\"AccessToken\":\"abcdefgh\"}");
        assertFalse(out.contains("abcdefgh"));
        assertTrue(out.contains("AccessToken"));
    }

    @Test public void truncatesLongBodyAndReportsRealLength() {
        StringBuilder raw = new StringBuilder("{\"x\":\"");
        for (int i = 0; i < ProbeRedactor.MAX_BODY + 500; i++) {
            raw.append('a');
        }
        raw.append("\"}");
        String out = ProbeRedactor.body(raw.toString());

        assertTrue(out.startsWith("{\"x\":\""));
        assertTrue(out.contains("共 " + raw.length() + " 字符"));
        assertTrue(out.length() < raw.length());
    }

    /** 菜单响应实测 1.6 万字符，截短了会正好丢掉要找的入口，所以这个长度必须留全。 */
    @Test public void keepsMenuSizedBodyIntact() {
        StringBuilder raw = new StringBuilder("{\"data\":[");
        while (raw.length() < 16552) {
            raw.append("{\"name\":\"x\"},");
        }
        raw.append("]}");
        assertEquals(raw.toString(), ProbeRedactor.body(raw.toString()));
    }

    @Test public void masksPersonalFieldsNotJustCredentials() {
        String raw = "{\"real_name\":\"张三\",\"phone\":\"13800000000\",\"number\":\"200000000000\","
                + "\"nickname\":\"小张\",\"remain\":196.33}";
        String out = ProbeRedactor.body(raw);

        assertFalse(out.contains("张三"));
        assertFalse(out.contains("13800000000"));
        assertFalse(out.contains("200000000000"));
        assertFalse(out.contains("小张"));
        assertTrue(out.contains("\"remain\":196.33"));
    }

    @Test public void masksTokenCarriedInUrlQuery() {
        String url = "https://vdurl.com/applet/link/route.jhtml?id=11311&appletId=20849"
                + "&token=b918701ff7d8b7e0d7cd74065f04e0b3&vdpath=%2Fpages%2Findex";
        String out = ProbeRedactor.url(url);

        assertFalse(out.contains("b918701ff7d8b7e0d7cd74065f04e0b3"));
        assertTrue(out.contains("id=11311"));
        assertTrue(out.contains("appletId=20849"));
        assertTrue(out.contains("vdpath=%2Fpages%2Findex"));
    }

    /** 微信授权链把转接令牌 URL 编码后嵌进 redirect_uri，只认 ?token= 会漏掉。夹具全用合成值。 */
    @Test public void masksTokenNestedInsideEncodedRedirectUri() {
        String url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=wxTESTONLY"
                + "&redirect_uri=http%3A%2F%2Fvendor.example.com%2Fbase%2Fips%3Fsaas_wap_token%3D"
                + "FAKE0000TESTTOKEN0000%26tenantCode%3DS00000&scope=snsapi_base";
        String out = ProbeRedactor.url(url);

        assertFalse(out.contains("FAKE0000TESTTOKEN0000"));
        assertTrue(out.contains("appid=wxTESTONLY"));
        assertTrue(out.contains("scope=snsapi_base"));
        assertTrue(out.contains("tenantCode%3DS00000"));
    }

    @Test public void emptyBodyIsLabelled() {
        assertEquals("(空)", ProbeRedactor.body(null));
        assertEquals("(空)", ProbeRedactor.body(""));
    }

    @Test public void headerValuesAreNeverKept() {
        assertEquals("Authorization,X-Token", ProbeRedactor.headerNames("Authorization, X-Token"));
        assertEquals("(无自定义头)", ProbeRedactor.headerNames(null));
        assertEquals("(无自定义头)", ProbeRedactor.headerNames("  "));
    }

    @Test public void cookieValuesAreNeverKept() {
        assertEquals("JSESSIONID,uid", ProbeRedactor.cookieNames("JSESSIONID=abc123; uid=42"));
        assertEquals("(无 Cookie)", ProbeRedactor.cookieNames(null));
    }

    @Test public void requestLineCarriesMethodUrlStatusAndRedactedBody() {
        String line = ProbeRedactor.request("POST", "https://x/api/power", 200,
                "Authorization", "{\"token\":\"secretvalue\",\"remain\":12.5}");

        assertTrue(line.startsWith("POST https://x/api/power → 200"));
        assertTrue(line.contains("头[Authorization]"));
        assertFalse(line.contains("secretvalue"));
        assertTrue(line.contains("12.5"));
    }
}