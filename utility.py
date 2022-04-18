

def get_rows_form(vector, row_size):
    matrix = []

    temp = []
    for idx, item in enumerate(vector):
        temp.append(item)

        if (idx + 1) % row_size == 0:
            matrix.append(temp)
            temp = []

    if len(temp) > 0:
        matrix.append(temp)
    
    return matrix

def get_columns_form(vector, row_size):

    # if len(vector) % column_size != 0:
    #     mat_size = len(vector) // column_size + 1

    # else:
    #     mat_size = len(vector) // column_size
    
    mat_size = row_size
    matrix = []
    for i in range(mat_size):
        matrix.append([])
    for idx, item in enumerate(vector):
        matrix[(idx % mat_size)].append(item)
    
    return matrix

def get_vector_form(matrix, form = "row"):
    vector = []
    
    if form == "row":
        for row in matrix:
            vector += row

    else:
        vector = len(matrix) * len(matrix[0]) * [0]

        for idx in range(len(vector)):
            vector[idx] = matrix[idx % len(matrix)][idx // len(matrix)]
    
    return vector

def get_xor(w1: bytes, w2: bytes):
    result = []

    for idx, b in enumerate(w1):
        result.append(b ^ w2[idx])

    return bytes(result)