package com.tatar.selsup;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class CrptApi {

    private static final Logger logger = Logger.getLogger(CrptApi.class.getName());

    //private static final String API_URL = "https://markirovka.demo.crpt.tech/api/v3/lk/documents/create";
    private static final String API_URL = "https://ismp.crpt.ru/api/v3/lk/documents/create";
    //private static final String API_URL = "https://markirovka.crpt.ru/api/v3/lk/documents/create";
    private static final String AUTH_URL = "https://ismp.crpt.ru";


    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private final int requestLimit;

    private final Semaphore semaphore;
    private final CloseableHttpClient httpClient;
    private final CloseableHttpClient authHttpClient;
    private final ScheduledExecutorService scheduler;

    //ключ УКЭП от личного кабинета в чз
    //выделил метод, который надо реализовать
    private final PrivateKey privateKey;

    private String authToken;
    private long tokenExpiryTime;

    public CrptApi(TimeUnit timeUnit, int requestLimit) {
        if (requestLimit < 1) {
            logger.warning("Неверное значение количества запросов");
            throw new IllegalArgumentException("Количество запросов должно быть положительным");
        }

        this.requestLimit = requestLimit;
        this.semaphore = new Semaphore(requestLimit);


        PoolingHttpClientConnectionManager manager = new PoolingHttpClientConnectionManager();
        manager.setMaxTotal(100);
        manager.setDefaultMaxPerRoute(20);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofSeconds(10))
                .setResponseTimeout(Timeout.ofSeconds(30))
                .build();


        this.httpClient = HttpClients.custom()
                .setConnectionManager(manager)
                .setDefaultRequestConfig(requestConfig)
                .build();

        this.authHttpClient = HttpClients.createDefault();

        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::resetRequestCounter, 1, 1, timeUnit);

        this.privateKey = this.loadPrivateKey();
    }

    //Вызывает универсальное создание документа(но тк только в оборот, то не все типы в моедли)
    public void createDocument(Document document, String signature) {
        try {
            semaphore.acquire();

            if (authToken == null || System.currentTimeMillis() > tokenExpiryTime) {
                authToken = this.getAuthToken();
                tokenExpiryTime = System.currentTimeMillis() + (10 * 60 * 60 * 1000); // 10 часов
            }

            document.setSignature(Base64.getEncoder().encodeToString(signature.getBytes(StandardCharsets.UTF_8)));
            //document.setProduct_document(Base64.getEncoder().encodeToString(OBJECT_MAPPER.writeValueAsBytes(document)));//?: "product_document":"<Документ в base64>"

            String documentJson = OBJECT_MAPPER.writeValueAsString(document);

            HttpPost request = new HttpPost(API_URL + "?pg=" + document.product_group.value);
            request.setHeader("Authorization: Bearer ", authToken);
            request.setHeader("Content-Type", "application/json");
            //request.setHeader("Signature", signature);
            request.setEntity(new StringEntity(documentJson, ContentType.APPLICATION_JSON));

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                String responseBody = EntityUtils.toString(response.getEntity());

                if (response.getCode() != 200) {
                    throw new ApiException("Ошибка обращения: " + responseBody);
                }
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Запрос прерван", e);
        } catch (Exception e) {
            throw new RuntimeException("Не удалось создать документ", e);
        } finally {
            semaphore.release();
        }
    }

    private void resetRequestCounter() {
        int availablePermits = semaphore.availablePermits();
        if (availablePermits < requestLimit) {
            semaphore.release(requestLimit - availablePermits);
        }
    }

    private String getAuthToken() throws Exception {
        AuthChallenge challenge = this.getAuthChallenge();

        String signedData = this.signData(challenge.getData());

        return this.getTokenBlocks(challenge.getUuid(), signedData);
    }

    private AuthChallenge getAuthChallenge() throws Exception {
        HttpGet request = new HttpGet(AUTH_URL + "/api/v3/auth/cert/key");

        try (CloseableHttpResponse response = authHttpClient.execute(request)) {
            String responseBody = EntityUtils.toString(response.getEntity());

            if (response.getCode() != 200) {
                throw new ApiException("Ошибка при получении: " + responseBody);
            }

            return OBJECT_MAPPER.readValue(responseBody, AuthChallenge.class);
        }
    }

    private String getTokenBlocks(String uuid, String signedData) throws Exception {
        HttpPost request = new HttpPost(AUTH_URL + "/api/v3/auth/cert");
        request.setHeader("Content-Type", "application/json");

        AuthRequest authRequest = new AuthRequest(uuid, signedData);
        String jsonBody = OBJECT_MAPPER.writeValueAsString(authRequest);
        request.setEntity(new StringEntity(jsonBody, ContentType.APPLICATION_JSON));

        try (CloseableHttpResponse response = authHttpClient.execute(request)) {
            String responseBody = EntityUtils.toString(response.getEntity());

            if (response.getCode() != 200) {
                throw new ApiException("Ошибка при получении токена: " + responseBody);
            }

            AuthResponse authResponse = OBJECT_MAPPER.readValue(responseBody, AuthResponse.class);

            if (authResponse.getToken() == null) {
                throw new ApiException("Не удалось получить токен: " +
                        authResponse.getErrorMessage() + " - " + authResponse.getDescription());
            }

            return authResponse.getToken();
        }
    }

    private String signData(String data) throws Exception {
        Signature signature = Signature.getInstance("GOST341WITHECGOST3410");
        signature.update(data.getBytes("UTF-8"));
        signature.initSign(privateKey);
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

    // Метод для загрузки приватного ключа (должен быть реализован)
    private PrivateKey loadPrivateKey() {
        // Реализация загрузки приватного ключа
        return null;
    }

    public void shutdown() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }

            httpClient.close();
            authHttpClient.close();
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            logger.warning(e.getMessage());
        }
    }


    // DTO классы для Java 11
    public static class AuthChallenge {
        private String uuid;
        private String data;

        public AuthChallenge() {
        }

        public AuthChallenge(String uuid, String data) {
            this.uuid = uuid;
            this.data = data;
        }

        public String getUuid() {
            return uuid;
        }

        public void setUuid(String uuid) {
            this.uuid = uuid;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }
    }

    public static class AuthRequest {
        private String uuid;
        private String data;

        public AuthRequest() {
        }

        public AuthRequest(String uuid, String data) {
            this.uuid = uuid;
            this.data = data;
        }

        public String getUuid() {
            return uuid;
        }

        public void setUuid(String uuid) {
            this.uuid = uuid;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }
    }

    public static class AuthResponse {
        private String token;
        private String code;
        private String errorMessage;
        private String description;

        public AuthResponse() {
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }
    }


    // Модели данных
    public static class Document {

        @JsonIgnore
        public ProductGroup product_group;

        public String product_document; //Документ в base64 (Содержимое документа. Base64 (JSON.stringify))
        public DocumentFormat document_format;
        public DocumentType type;
        public String signature;


        public Document() {
        }

        public Document(DocumentFormat document_format,
                        String product_document,
                        ProductGroup product_group,
                        String signature,
                        DocumentType type) {
            this.document_format = document_format;
            this.product_document = product_document;
            this.product_group = product_group;
            this.signature = signature;
            this.type = type;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }

        public void setProduct_document(String product_document) {
            this.product_document = product_document;
        }
    }

    enum ProductGroup {
        CLOTHES("clothes"),
        SHOES("shoes"),
        TOBACCO("tobacco"),
        PERFUMERY("perfumery"),
        TIRES("tires"),
        ELECTRONICS("electronics"),
        PHARMA("pharma"),
        MILK("milk"),
        BICYCLE("bicycle"),
        WHEELCHAIRS("wheelchairs");

        private final String value;

        ProductGroup(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    enum DocumentFormat {
        MANUAL("MANUAL"),
        XML("XML"),
        CSV("CSV");

        private final String value;

        DocumentFormat(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    enum DocumentType {
        LP_INTRODUCE_GOODS("LP_INTRODUCE_GOODS"),
        LP_INTRODUCE_GOODS_XML("LP_INTRODUCE_GOODS_XML"),
        LP_INTRODUCE_GOODS_CSV("LP_INTRODUCE_GOODS_CSV");

        private final String value;

        DocumentType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    public static class ApiException extends RuntimeException {
        public ApiException(String message) {
            super(message);
        }

    }

}
