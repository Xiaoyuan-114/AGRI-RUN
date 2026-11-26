package org.localroute.app.ui;

import android.annotation.SuppressLint;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import org.localroute.app.R;
import org.localroute.app.databinding.ActivityPowerProbeBinding;
import org.localroute.app.diagnostics.DiagnosticLog;
import org.localroute.app.power.ProbeRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 宿舍电量取证页：只观察学校 H5 自己发出的请求，判断能不能接、怎么接。
 *
 * <p>账号密码只在官方页面里输入，本页不读表单、不存密码。记录里凭据一律只留名字与长度
 * （见 {@link ProbeRedactor}），保留的是接口路径、状态码、请求头名字、响应结构——判断接法
 * 需要的正是这些，不需要凭据的值。
 *
 * <p>这是试验性入口，不写任何绑定信息，也不影响首页那张卡；跑通后另写正式的客户端。
 */
public class PowerProbeActivity extends AppCompatActivity {

    private static final String START_URL = "https://goliveplus.zafu.edu.cn/saas_wap/";
    private static final String ALLOWED_SUFFIX = ".zafu.edu.cn";
    private static final int MAX_RECORDS = 400;

    /**
     * 厂商门槛嗅探用的 UA：只改标识，不伪造任何授权凭据。
     *
     * <p>用户知情后要求验证「请用微信打开」到底是 UA 嗅探还是真授权。若只是嗅探，换标识就会放行；
     * 若厂商真要 openid，换了也照样拦——两种结果都是有用的结论。这是取证手段，不是常驻绕过。
     */
    private static final String UA_WECHAT =
            "Mozilla/5.0 (Linux; Android 13; PJD110 Build/TP1A.220905.001; wv) "
            + "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 "
            + "Mobile Safari/537.36 MMWEBID/1234 MicroMessenger/8.0.49.2600(0x28003137) "
            + "WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64";

    private static final String UA_ALIPAY =
            "Mozilla/5.0 (Linux; U; Android 13; zh-CN; PJD110 Build/TP1A.220905.001) "
            + "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 "
            + "Mobile Safari/537.36 AliApp(AP/10.5.36.8000) AlipayClient/10.5.36.8000 "
            + "Language/zh-Hans";

    /**
     * 页面里挂的钩子：包住 XHR 与 fetch，把方法、地址、状态、请求头名字与响应片段交回来。
     *
     * <p>只观察不改写，原请求照常发出；重复注入用 {@code __powerProbe} 挡住。
     */
    private static final String HOOK_JS =
            "(function(){"
            + "if(window.__powerProbe)return;window.__powerProbe=true;"
            + "var o=XMLHttpRequest.prototype.open,s=XMLHttpRequest.prototype.send,"
            + "h=XMLHttpRequest.prototype.setRequestHeader;"
            + "XMLHttpRequest.prototype.open=function(m,u){this.__m=m;this.__u=u;this.__h=[];"
            + "return o.apply(this,arguments)};"
            + "XMLHttpRequest.prototype.setRequestHeader=function(k,v){this.__h.push(k);"
            + "return h.apply(this,arguments)};"
            + "XMLHttpRequest.prototype.send=function(){var t=this;"
            + "this.addEventListener('load',function(){try{AndroidProbe.record(t.__m,t.__u,"
            + "t.status,(t.__h||[]).join(','),String(t.responseText||''))}catch(e){}});"
            + "return s.apply(this,arguments)};"
            + "var f=window.fetch;"
            + "if(f)window.fetch=function(i,n){"
            + "var u=typeof i==='string'?i:(i&&i.url);"
            + "var m=(n&&n.method)||(i&&i.method)||'GET';var hs=[];"
            + "try{var hh=(n&&n.headers)||{};"
            + "if(hh.forEach)hh.forEach(function(v,k){hs.push(k)});"
            + "else Object.keys(hh).forEach(function(k){hs.push(k)})}catch(e){}"
            + "return f.apply(this,arguments).then(function(r){try{r.clone().text()"
            + ".then(function(x){AndroidProbe.record(m,u,r.status,hs.join(','),x)})}catch(e){}"
            + "return r})};"
            + "})();";

    /** 存储只取键名与长度，用来判断会话是不是放在 localStorage 的 token 里。 */
    private static final String STORAGE_JS =
            "(function(){var o=[];"
            + "try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);"
            + "o.push('local '+k+' len='+(localStorage.getItem(k)||'').length)}}catch(e){}"
            + "try{for(var j=0;j<sessionStorage.length;j++){var k2=sessionStorage.key(j);"
            + "o.push('session '+k2+' len='+(sessionStorage.getItem(k2)||'').length)}}catch(e){}"
            + "return o.join('\\n')})();";

    private final List<String> records = new ArrayList<>();
    private ActivityPowerProbeBinding binding;
    /** 0 默认、1 微信、2 支付宝。 */
    private int uaMode;

    @SuppressLint("SetJavaScriptEnabled")
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        binding = ActivityPowerProbeBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });

        WebView web = binding.probeWeb;
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);
        web.getSettings().setAllowFileAccess(false);
        web.getSettings().setAllowContentAccess(false);
        web.addJavascriptInterface(new ProbeBridge(), "AndroidProbe");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view,
                                                              WebResourceRequest request) {
                Uri url = request.getUrl();
                String scheme = url.getScheme();
                if (scheme == null) {
                    return true;
                }
                if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
                    // weixin:// 之类：说明这个入口要跳小程序而不是 H5，这正是要取证的结论之一。
                    // 记下来，但不交给系统去拉起别的应用。
                    add("EXTERNAL-SCHEME " + ProbeRedactor.url(url.toString()));
                    return true;
                }
                if (!allowed(url)) {
                    // 菜单里的外链指向厂商域名，挡住会让按钮点了没反应；放行并标记。
                    add("OFFSITE " + request.getMethod() + " " + ProbeRedactor.url(url.toString()));
                }
                return false;
            }

            @Override public WebResourceResponse shouldInterceptRequest(WebView view,
                                                                        WebResourceRequest request) {
                Uri url = request.getUrl();
                if (allowed(url)) {
                    Map<String, String> headers = request.getRequestHeaders();
                    StringBuilder names = new StringBuilder();
                    if (headers != null) {
                        for (String key : headers.keySet()) {
                            if (key == null) continue;
                            if (names.length() > 0) names.append(',');
                            names.append(key);
                        }
                    }
                    add("NAV " + request.getMethod() + " " + ProbeRedactor.url(url.toString())
                            + " | 头[" + ProbeRedactor.headerNames(names.toString()) + "]");
                }
                return null;
            }

            @Override public void onPageFinished(WebView view, String url) {
                add("PAGE " + ProbeRedactor.url(url));
                if (!allowed(Uri.parse(url))) return;
                add("COOKIE " + ProbeRedactor.cookieNames(
                        CookieManager.getInstance().getCookie(url)));
                view.evaluateJavascript(HOOK_JS, null);
                view.evaluateJavascript(STORAGE_JS, value -> {
                    if (value != null && !value.equals("null") && !value.isEmpty()) {
                        add("STORAGE " + value.replace("\\n", " / ").replace("\"", ""));
                    }
                });
            }
        });

        binding.buttonProbeCopy.setOnClickListener(v -> copyRecords());
        binding.buttonProbeClear.setOnClickListener(v -> {
            synchronized (records) {
                records.clear();
            }
            refreshCount();
        });
        binding.buttonProbeGo.setOnClickListener(v -> {
            String url = binding.probeUrl.getText().toString().trim();
            if (!url.isEmpty()) {
                add("MANUAL " + ProbeRedactor.url(url));
                web.loadUrl(url);
            }
        });
        binding.buttonProbeUa.setOnClickListener(v -> cycleUserAgent());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (web.canGoBack()) {
                    web.goBack();
                } else {
                    finish();
                }
            }
        });
        refreshCount();
        web.loadUrl(START_URL);
    }

    @Override protected void onDestroy() {
        binding.probeWeb.removeJavascriptInterface("AndroidProbe");
        binding.probeWeb.destroy();
        super.onDestroy();
    }

    private static boolean allowed(Uri url) {
        String host = url == null ? null : url.getHost();
        if (host == null) return false;
        host = host.toLowerCase(Locale.US);
        return host.endsWith(ALLOWED_SUFFIX) || host.equals("zafu.edu.cn");
    }

    /** 默认 → 微信 → 支付宝 → 默认，换完立刻重载当前页，好让门槛重新判一次。 */
    private void cycleUserAgent() {
        uaMode = (uaMode + 1) % 3;
        String ua;
        int label;
        switch (uaMode) {
            case 1:
                ua = UA_WECHAT;
                label = R.string.power_probe_ua_wechat;
                break;
            case 2:
                ua = UA_ALIPAY;
                label = R.string.power_probe_ua_alipay;
                break;
            default:
                ua = null;
                label = R.string.power_probe_ua_default;
                break;
        }
        // null 让 WebView 回到自己的默认 UA，不用手写一份容易过期的字符串。
        binding.probeWeb.getSettings().setUserAgentString(ua);
        binding.buttonProbeUa.setText(label);
        add("UA " + getString(label) + " → "
                + binding.probeWeb.getSettings().getUserAgentString());
        Toast.makeText(this, R.string.power_probe_ua_note, Toast.LENGTH_LONG).show();
        binding.probeWeb.reload();
    }

    private void add(String line) {
        synchronized (records) {
            records.add(line);
            while (records.size() > MAX_RECORDS) {
                records.remove(0);
            }
        }
        DiagnosticLog.info(line);
        runOnUiThread(this::refreshCount);
    }

    private void refreshCount() {
        int size;
        synchronized (records) {
            size = records.size();
        }
        binding.textProbeCount.setText(getString(R.string.power_probe_count, size));
    }

    private void copyRecords() {
        String text;
        synchronized (records) {
            text = String.join("\n", records);
        }
        if (text.isEmpty()) {
            Toast.makeText(this, R.string.power_probe_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("power-probe", text));
        Toast.makeText(this, R.string.power_probe_copied, Toast.LENGTH_SHORT).show();
    }

    /** 页面 → 本机的唯一通道；只收字符串，不做任何回写。 */
    private final class ProbeBridge {
        @JavascriptInterface
        public void record(String method, String url, int status, String headers, String body) {
            add("API " + ProbeRedactor.request(method, url, status, headers, body));
        }
    }
}