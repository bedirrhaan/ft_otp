NAME = ft_otp

all: $(NAME)

$(NAME): ft_otp.py
	cp ft_otp.py $(NAME)
	chmod +x $(NAME)

bonus: $(NAME)
	python3 -m pip install --user qrcode pillow

clean:
	rm -f ft_otp.key ft_otp.png key.hex

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all bonus clean fclean re
