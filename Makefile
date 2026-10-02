NAME = ft_otp

all: $(NAME)

$(NAME): ft_otp.py
	cp ft_otp.py $(NAME)
	chmod +x $(NAME)

bonus:
	python3 -m pip install --user qrcode pillow

clean:
	rm -f ft_otp.key ft_otp.png

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all bonus clean fclean re
