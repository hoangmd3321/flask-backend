import pandas as pd

mapping_keys = {'ID': 'id', 'Description': 'descriptions', 'Message': 'message', 'Toast': 'toast',
                'Duration': 'duration', 'Type': 'status'}


def my_read_excel():
    """

    :return:
    """
    file_name = "MN_VI_Quan_ly_message_v1_08102021.xlsx"
    use_cols = ['ID', 'Description', 'Message', 'Toast', 'Duration', 'Type']
    df = pd.read_excel(file_name, header=0, usecols=use_cols)
    print(type(df))

    messages = []
    for i in range(len(df)):
        tmp = {}  
        for key, new_key in mapping_keys.items():
            if key == "Toast":
                tmp.setdefault(new_key, bool(df[key][i]))
            elif key == "Duration":
                tmp.setdefault(new_key, int(df[key][i]))
            else:
                tmp.setdefault(new_key, str(df[key][i]).strip())
        dt.append(tmp)
    return dt
#
#
# def get_current_messages(table_name='IMSMessages', dynamodb=None):
#     """
#
#     :param table_name:
#     :param dynamodb:
#     :return:
#     """
#     if not dynamodb:
#         dynamodb = boto3.resource('dynamodb')
#
#     table = dynamodb.Table(table_name)
#
#     data = table.scan()
#     list_messages = []
#     if 'Items' in data:
#         for item in data['Items']:
#             list_messages.append({
#                 'id': item['id'],
#                 'popup': item['popup'],
#                 'status': item['status'],
#                 'text': item['text'],
#                 'duration': int(item['duration']),
#                 'descriptions': item['descriptions'],
#                 'text_de': item['text_de'] if 'text_de' in item.keys() else ''
#             })
#     return list_messages
#
#
# def update_message(table_name='IMSMessages', dynamodb=None):
#     """
#
#     :param table_name:
#     :param dynamodb:
#     :return:
#     """
#     if not dynamodb:
#         dynamodb = boto3.resource('dynamodb')
#
#     table = dynamodb.Table(table_name)
#
#     messages = my_read_excel()
#     current_messages = get_current_messages(table_name)
#     for message in messages:
#         existed_message = next((item for item in current_messages if item.get('id') == message.get('id')), None)
#         if existed_message and existed_message != message:
#             response = table.update_item(
#                 Key={
#                     "id": message.get('id')
#                 },
#                 UpdateExpression="set #attrPopup=:newPopup, #attrStatus=:newStatus, #attrText=:newText, #attrTextDE=:newTextDE, #attrDuration=:newDuration, "
#                                  "#attrDescriptions=:newDescriptions",
#                 ExpressionAttributeValues={
#                     ":newPopup": message.get('popup'),
#                     ":newStatus": message.get('status'),
#                     ":newText": message.get('text'),
#                     ":newTextDE": message.get('text_de'),
#                     ":newDuration": message.get('duration'),
#                     ":newDescriptions": message.get('descriptions')
#                 },
#                 ExpressionAttributeNames={
#                     "#attrPopup": "popup",
#                     "#attrStatus": "status",
#                     "#attrText": "text",
#                     "#attrTextDE": "text_de",
#                     "#attrDuration": "duration",
#                     "#attrDescriptions": "descriptions"
#                 },
#                 ReturnValues="UPDATED_NEW"
#             )
#             print("UPDATED: ", message)
#
#         if existed_message is None:
#             print("ADDED: ", message)
#             table.put_item(Item=message)


if __name__ == '__main__':
    update_table = "IMSMessages"
    print(my_read_excel())
