# A REST API declared for deployment whose handler is nowhere in the code.
resource "aws_api_gateway_rest_api" "this" {
  name = "five-views"
}

resource "aws_api_gateway_resource" "ghost" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "ghost-function"
}

resource "aws_api_gateway_method" "ghost" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  resource_id   = aws_api_gateway_resource.ghost.id
  http_method   = "GET"
  authorization = "NONE"
}
