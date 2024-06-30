package email

import (
	"bytes"
	"fmt"
	"gopkg.in/gomail.v2"
	"html/template"
)

type EmailConnection struct {
	server   string
	port     int
	username string
	password string
}

func SendPlainMail(
	from string,
	to []string,
	subject string,
	text string,
	conn EmailConnection,
) {
	message := gomail.NewMessage()
	message.SetHeader("From", from)
	message.SetHeader("To", to...)
	message.SetHeader("Subject", subject)
	message.SetBody("text/plain", text)

	d := gomail.NewDialer(conn.server, conn.port, conn.username, conn.password)
	if err := d.DialAndSend(message); err != nil {
		fmt.Println(err)
	}
}

func SendHTMLMail(
	from string,
	to []string,
	subject string,
	html string,
	data interface{},
	conn EmailConnection,
) {
	tmpl, err := template.ParseFiles(html)
	if err != nil {
		fmt.Println(err)
		return
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		fmt.Println(err)
		return
	}

	message := gomail.NewMessage()
	message.SetHeader("From", from)
	message.SetHeader("To", to...)
	message.SetHeader("Subject", subject)
	message.SetBody("text/html", body.String())

	d := gomail.NewDialer(conn.server, conn.port, conn.username, conn.password)
	if err := d.DialAndSend(message); err != nil {
		fmt.Println(err)
		return
	}
}
