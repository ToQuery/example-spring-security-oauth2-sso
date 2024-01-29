package io.github.toquery.example.spring.security.oauth2.jwt.core.properties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 暂时还未用到，jwt 由SSO下发
 *
 * @author ToQuery
 */
@Slf4j
@Data
@ConfigurationProperties(prefix = "app.jwt")
public class AppJwtProperties {

    private String keyId = "123456";

    private String publicKey = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzCUJNkxbcBUyWFDXy1k4
            J1IdV+v9zgFjFBtvoXE+ipbHnu7y/h95HiR0MJ/vT4jqylM+tPUUlsYaZmKjRDGe
            KPPGNZN9qwvNIJ83sb8m9UBQFZydj6rjCwAqwQyKJ1bi69TLdO2UJSsFCjqXeYzJ
            PG8+hNy3i2Zkl5glmIJvU8JQIocsE51/ObKMUXHAVjOsBD8UTOnt+eBhDviM9nnr
            Mk8FiFQNP0xvh2ayxlN/ouVSAt9Ky2OsWdVHOrtS84zSPTxyWnAx9uQDP6G+3TX5
            YOjWsUdCR2f6hVvClU94aJNtapCxGwmgP4qbHbZUKRIqp3lXmHz1OkjYMQaqIsqX
            TwIDAQAB
            -----END PUBLIC KEY-----
            """;

    private String privateKey = """
            -----BEGIN PRIVATE KEY-----
            MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDMJQk2TFtwFTJY
            UNfLWTgnUh1X6/3OAWMUG2+hcT6Klsee7vL+H3keJHQwn+9PiOrKUz609RSWxhpm
            YqNEMZ4o88Y1k32rC80gnzexvyb1QFAVnJ2PquMLACrBDIonVuLr1Mt07ZQlKwUK
            Opd5jMk8bz6E3LeLZmSXmCWYgm9TwlAihywTnX85soxRccBWM6wEPxRM6e354GEO
            +Iz2eesyTwWIVA0/TG+HZrLGU3+i5VIC30rLY6xZ1Uc6u1LzjNI9PHJacDH25AM/
            ob7dNflg6NaxR0JHZ/qFW8KVT3hok21qkLEbCaA/ipsdtlQpEiqneVeYfPU6SNgx
            BqoiypdPAgMBAAECggEBAJiSBXSDVMNL1DiVEvJzV7hrcmrHgQR5nObmKmPqEufZ
            EJAD3a93LjoM3JmKrnwuw+s6k98CW8Tjgc+LYKISwzWwGy7ncEBprYD3/dPmHOOm
            kTPVvRwmh1Etasak7IvCMA45F2XoOZQdtsKST6sUQUHdkkgR/Us912hE2bRFp5Zc
            iXirx6adTayNoaorVoZEiqKWj/Io00ugb5kOBn04bOfC4mDOVlsQMWrfShJLzJlF
            8LXrrCsddsWnBUUJ4rkZd1+JUT9a+iRVaOqRyLID/LtkPPYdgLKsS3i7F2l0Xzvg
            yHoCreb9FQbvhXjaFSbqN3wR9jVq9s4sUCBk885GlGECgYEA5btXyVzFoBibQMUO
            OaGgr7cYSSZI7dOZF+BMiJxrR3XfQPqHImd2OkCeLRcKDyYC3enmEybtiXYNhp48
            yrqlzfKvP+1SULP2IwmbsEwPms0hQxEAmxH5T87uFoAQaj0xheO58KegeTZSlZpi
            dKZgz/nhYrNfxozbzI7HjmEPl6sCgYEA43y2VdgfE93b/iH4MEpaaGnUOHeYgUQC
            RxAee4B31HfX7wRAvmN6kouVNnYzzpUUvoEmB6sZ6Gs+t0llNzGq8y85ILxfPyf2
            UMWNs7q1WwFoffm+LokYSnmDr50DorAYxYoACuPfQNBJn2dbaOx2R+RhxqcuzirJ
            MHJICNHLiu0CgYBnmCiJDAWuIQp5laLJiEH+mtEfw1zlqiKCKso4XFjgG542HgMs
            F32v3Q23BYmqtRhb26q9fjNlZk/JIbgGL06vZT1z1V/mNpDK0f1b7aCnzNKv/I3K
            X7uOKqEgklVUow2e88cYZ26s2js5bSnyskg74NGrAXox/bjsMIJ6iPhQCwKBgQDU
            S0Y9xnr6J0luWHUtW7YTSu/p4nJH8BfQCZLo3nL1rQGu5OEmy99Pc0PEl3qxhx7c
            ydmbvmlnJO5aTfxPDeLjH2bIzgJ1Be4wYqxi1hL44s+JANAizX4FwnDKKlWCNaRo
            dOilQRLPgZGzWNlNiZ64aMF2if58GCG5PG1NDbxN4QKBgQDaEwMWx+eG0Ve+FO0V
            4/hDhXvELcdVq6F08DgB+2Ie2hhxkKIxAGmUHuXurm5wPhXhO6Ms6T7ig2plGiar
            /zkmZVRWMEX5fNsQJC/1HFEHdFiUqNU+2PKF9zzbhp1aSBb1Q6CpqEcPzxcsXJ3B
            Jr8LOHMlb/Ax5ohgnFOyZ1Pyrw==
            -----END PRIVATE KEY-----
            """;


}
