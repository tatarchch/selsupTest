package com.tatar.selsup;

import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class Main {

    private static final Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        try {
            CrptApi crptApi = new CrptApi(TimeUnit.SECONDS, 3);

            CrptApi.Document document = new CrptApi.Document(
                    CrptApi.DocumentFormat.MANUAL,
                    "Product_document",
                    CrptApi.ProductGroup.MILK,
                    "Signature",
                    CrptApi.DocumentType.LP_INTRODUCE_GOODS
            );

            logger.info("отправка документа");
            crptApi.createDocument(document, "Signature");
            logger.info("документ отправлен");

            Thread.sleep(5000);

            crptApi.shutdown();
        } catch (Exception e) {
            logger.warning("Ошибка при тестировании: " + e.getMessage());
            e.printStackTrace();
        }
    }
}


