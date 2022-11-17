def get_date_details(bill_state):
    from datetime import date

    monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    today = date.today()
    # index starts with 0
    first_month_name = monthNames[today.month - 1]
    firstDay = today.replace(day=1)
    first_day_str = str(firstDay)

    last_month_name = monthNames[today.month - 2]
    last_month_first_day_str = str(today.replace(day=1, month=(today.month - 1)))
    second_last_month_name = monthNames[today.month - 3]
    if bill_state == 'current':
        return [first_month_name, first_day_str, last_month_name]
    else:
        return [last_month_name, last_month_first_day_str, second_last_month_name]