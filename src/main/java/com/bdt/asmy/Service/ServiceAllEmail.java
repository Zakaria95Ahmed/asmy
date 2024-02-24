package com.bdt.asmy.Service;

import com.sun.mail.smtp.SMTPTransport;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Properties;

import static jakarta.mail.Message.RecipientType.CC;
import static jakarta.mail.Message.RecipientType.TO;

@Service
public class ServiceAllEmail {

//    private  JavaMailSender mailSender;
    public void sendNewPasswordEmail(String firstName, String password, String email) throws MessagingException {
        Message message = createEmail(firstName, password, email);
//        bagv jodm llbw yfzi
        SMTPTransport smtpTransport = (SMTPTransport) getEmailSession().getTransport("smtps");
//        smtpTransport.connect("smtp.gmail.com", "zakariayahmed@gmail.com", "Pa$$word");
        smtpTransport.connect("smtp.gmail.com", "zakariayahmed@gmail.com", "bagv jodm llbw yfzi");
        smtpTransport.sendMessage(message, message.getAllRecipients());
        smtpTransport.close();
    }

    private Message createEmail(String firstName, String password, String email) throws MessagingException {
        Message message = new MimeMessage(getEmailSession());
        message.setFrom(new InternetAddress("zakariayahmed@gmail.com"));
        message.setRecipients(TO, InternetAddress.parse(email, false));
        message.setRecipients(CC, InternetAddress.parse("mohandes30zakaria@gmail.com", false));
        message.setSubject("ZAGZAG-Company, ZAG-Co.electronic-ltd - New Password");
        message.setText("Hello " + firstName + ", \n \n Your new account password is: " + password + "\n \n The Support Team"+"\n From ASMY BDT");
        message.setSentDate(new Date());
        message.saveChanges();
        return message;
    }

    private Session getEmailSession() {
        Properties properties = System.getProperties();
        properties.put("mail.smtp.host", "smtp.gmail.com");
        properties.put("mail.smtp.auth", true);
//        properties.put("mail.smtp.port", 465);
        properties.put("mail.smtp.port", 587);
        properties.put("mail.smtp.starttls.enable", true);
        properties.put("mail.smtp.starttls.required", true);
        return Session.getInstance(properties, null);
    }





}
