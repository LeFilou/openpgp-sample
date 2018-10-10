import java.io.FileInputStream;

public class Main {

    private static String key = "salim";
    private static String pubKeyFile = "pubring.pkr";
    private static String privKeyFile = "secret.pkr";

    public static void main(String[] args) throws Exception {
        String data = "hQEMAzqNymHq1a2aAQf/XOr6jn+DIglFQ8hqL143pQ41j9q2cROWt0taDOMdMsQ3zoj2" +
                "TArQOAi00y165ihL6ItP6cC8SJE1CLrfM3leAB4GegxPEEYBCBZqmYDBQUqRizoVD37N93zG8h" +
                "aM7isVkdcNy/ExaWTN7OLyxxE9Opj4FuShDp9DXzkci8OMNdpMgq+p1sgZC1HmmnuEpi7SrpcE" +
                "Vo5wsjm0pE/8et0SLQRFORdypCY8FEFlBISeG08aOb1LJWDRsapkDl8EPG9koIe9llVGo5jhm3" +
                "/fjCRLOhcy6ddfQDQFxDIZxItvNMKWJi6CxHNs5Ynv4fj59s/SINcrId0JQgU9xCSAs/+e8NI6" +
                "AVs9z4HNoCPbnI/A4jmDyYkANU3gICgMhxRCSgbF2vP+xPd+tWsxg/jiKGcRCincU9mrV5HtL6" +
                "paRA===MS40";

        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        String s = PgpHelper.getInstance().decryptString(data, privKeyIn, key.toCharArray());
        System.out.println(s);
        privKeyIn.close();
    }


}
