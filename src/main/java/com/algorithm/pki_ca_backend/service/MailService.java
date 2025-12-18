package com.algorithm.pki_ca_backend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String from;

    public MailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    //测试用：发送一封简单文本邮件
//    public void sendTestMail(String to) {
//        SimpleMailMessage message = new SimpleMailMessage();
//        message.setFrom(from);
//        message.setTo(to);
//        message.setSubject("PKI CA 邮件功能测试");
//        message.setText("这是一封来自 PKI CA 系统的测试邮件，用于验证 Outlook SMTP 配置是否正常。");
//
//        mailSender.send(message);
//    }

    // 证书签发申请通过，发送通知邮件
    public void sendCertificateIssuedMail(String to, String username, String serialNumber) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("【PKI CA 系统】证书签发成功通知");
        message.setText(
                "您好，" + username + "：\n\n" +
                        "您的证书申请已通过管理员审核，证书已成功签发。\n\n" +
                        "证书序列号：\n" +
                        serialNumber + "\n\n" +
                        "请登录 PKI CA 系统下载并妥善保管您的证书。\n\n" +
                        "如非本人操作，请立即联系系统管理员。\n\n" +
                        "—— PKI CA 系统"
        );

        mailSender.send(message);
    }

    // 证书签发申请被拒绝，发送通知邮件
    public void sendCertificateIssueRejectedMail(String to,
                                                 String username,
                                                 String rejectReason) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("【PKI CA 系统】证书签发申请未通过");

        message.setText(
                "您好，" + username + "：\n\n" +
                        "很遗憾，您提交的证书签发申请未通过管理员审核。\n\n" +
                        "拒绝原因：\n" +
                        rejectReason + "\n\n" +
                        "如需修改申请信息，可重新提交签发申请。\n\n" +
                        "—— PKI CA 系统"
        );

        mailSender.send(message);
    }


    // 证书吊销申请通过，发送通知邮件
    public void sendCertificateRevokedMail(String to,
                                           String username,
                                           String serialNumber,
                                           String revokeReason) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("【PKI CA 系统】证书吊销申请已通过");

        message.setText(
                "您好，" + username + "：\n\n" +
                        "您提交的证书吊销申请已通过管理员审核，证书现已正式吊销。\n\n" +
                        "证书序列号：\n" +
                        serialNumber + "\n\n" +
                        "申请吊销原因：\n" +
                        revokeReason + "\n\n" +
                        "自吊销生效起，该证书将不再被信任，请勿继续使用。\n\n" +
                        "—— PKI CA 系统"
        );

        mailSender.send(message);
    }

    // 证书吊销申请被拒绝，发送通知邮件
    public void sendCertificateRevocationRejectedMail(String to,
                                                      String username,
                                                      String serialNumber,
                                                      String rejectReason) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("【PKI CA 系统】证书吊销申请未通过");

        message.setText(
                "您好，" + username + "：\n\n" +
                        "您提交的证书吊销申请未通过管理员审核，证书当前仍处于有效状态。\n\n" +
                        "证书序列号：\n" +
                        serialNumber + "\n\n" +
                        "拒绝原因：\n" +
                        rejectReason + "\n\n" +
                        "如仍需吊销，请确认原因后重新提交申请。\n\n" +
                        "—— PKI CA 系统"
        );

        mailSender.send(message);
    }


}

