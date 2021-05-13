package com.gaoy.security.oauthlogin.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.tomcat.jni.Multicast;

import javax.annotation.PostConstruct;
import java.util.Date;
import java.util.HashMap;

// 社交登录成功后，返回的信息
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Social {
    private String access_token;
    private Long remind_in;    // 本次accessToken有效时间（作废）
    private Long expires_in;    // 本次accessToken有效时间
    private String uid;  // 社交登录针对每个用户生成的唯一主键
    private Boolean isRealName;

    private Date expiresDate;

    public void setExpires_in(Long expires) {
        this.expires_in = expires;
        expiresDate = new Date(System.currentTimeMillis() + expires_in * 1000);
    }
}
